// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use x86_system::memory_core::cpu_core::apic::{
    Rejection,
    registers::{Effect, Error as ApicError},
    route::{FixedIpi, Interface},
    timer::{Deadline, Error as TimerError},
};
use x86_system::shared::control_io::{ControlAccess, ControlReply};

const TICKS_PER_100NS: u64 = 10;

pub(super) fn ticks(time: vmcore::vmtime::VmTime) -> Result<u64, Error> {
    time.as_100ns()
        .checked_mul(TICKS_PER_100NS)
        .ok_or(Error::Profile("APIC base-clock counter exhausted"))
}

impl Control {
    pub(super) fn publish_apic(&self, apic: &LocalApic) {
        self.routing.store(
            u64::from(apic.id) | (u64::from(apic.ldr) << 32) | (u64::from(apic.enabled()) << 40),
            Ordering::Release,
        );
    }

    fn post_apic(&self, vector: u8, level: bool) {
        if vector < 32 {
            self.unsupported.store(true, Ordering::Release);
            self.waker.wake();
            return;
        }
        let word = &self.incoming[usize::from(vector / 32)];
        let mask = 1u64 << (vector % 32);
        let mut old = word.load(Ordering::Acquire);
        loop {
            if old & mask != 0 {
                break;
            }
            let new = old | mask | if level { mask << 32 } else { 0 };
            match word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(current) => old = current,
            }
        }
        self.waker.wake();
    }

    pub(super) fn request_apic_msi(&self, request: virt::irqcon::MsiRequest) {
        if !self.has_apic || request.address >> 20 != 0xfee {
            self.unsupported.store(true, Ordering::Release);
            self.waker.wake();
            return;
        }
        let (address, data) = request.as_x86();
        if data.delivery_mode() > 1 {
            self.unsupported.store(true, Ordering::Release);
            self.waker.wake();
            return;
        }
        let routing = self.routing.load(Ordering::Acquire);
        let packet = FixedIpi {
            vector: data.vector(),
            destination: u32::from(address.virt_destination()),
            logical: address.destination_mode_logical(),
            shorthand: 0,
            interface: Interface::XApic,
        };
        // Lowest-priority and fixed routing coincide in the admitted one-VP profile.
        if packet.targets(
            0,
            routing as u32,
            (routing >> 32) as u8,
            routing & (1 << 40) != 0,
        ) {
            self.post_apic(packet.vector, data.trigger_mode_level());
        }
    }

    pub(super) fn apic_work_pending(&self) -> bool {
        self.incoming
            .iter()
            .any(|word| word.load(Ordering::Acquire) as u32 != 0)
    }
}

fn receive(apic: LocalApic, vector: u8, level: bool) -> Result<LocalApic, Error> {
    match apic.receive(vector, level) {
        Ok(next) => Ok(next),
        // An occupied IRR slot already represents this vector; do not make a FIFO.
        Err(Rejection::Retry) => Ok(apic),
        Err(other) => Err(Error::ApicIngress(other)),
    }
}

pub(super) fn effect(
    apic: &mut LocalApic,
    control: &Control,
    effect: Effect,
    dev: &impl CpuIo,
) -> Result<(), Error> {
    control.publish_apic(apic);
    match effect {
        Effect::None => {}
        Effect::Eoi(eoi) => {
            if eoi.broadcast {
                dev.handle_eoi(u32::from(eoi.vector.ok_or(Error::Completion)?));
            }
        }
        Effect::Ipi(packet) => {
            if packet.targets(apic.id, apic.id, apic.ldr, apic.enabled()) {
                *apic = receive(*apic, packet.vector, false)?;
            }
        }
    }
    Ok(())
}

pub(super) fn poll(
    state: &mut VpState,
    control: &Control,
    clock: &mut VmTimeAccess,
) -> Result<(), Error> {
    let (Some(apic), Some(core)) = (&mut state.lapic, &mut state.core) else {
        return Ok(());
    };
    if state.apic_offer.is_some() || !core.at_interrupt_boundary() {
        return Ok(());
    }
    // APIC register accesses materialize the counter themselves. With IF clear,
    // defer timer-only work until it can affect entry, observation, or a wait.
    if core.cpu().flags & 0x200 == 0 && !core.halted() && !control.apic_work_pending() {
        return Ok(());
    }
    let now = ticks(clock.now())?;
    if now < apic.timer.last {
        return Err(Error::Apic(ApicError::Timer(TimerError::BackwardsTime)));
    }
    // Counter reads/writes materialize time themselves. Between deadlines,
    // no timer effect is observable and the absolute deadline is unchanged.
    if matches!(apic.timer.deadline(),Deadline::At(deadline) if now>=deadline) {
        *apic = apic.advance(now).map_err(Error::Apic)?;
    }
    for (bank, slot) in control.incoming.iter().enumerate() {
        if slot.load(Ordering::Acquire) as u32 == 0 {
            continue;
        }
        let packet = slot.swap(0, Ordering::AcqRel);
        let mut pending = packet as u32;
        while pending != 0 {
            let bit = pending.trailing_zeros();
            let vector = (bank * 32 + bit as usize) as u8;
            *apic = receive(*apic, vector, packet & (1u64 << (bit + 32)) != 0)?;
            pending &= pending - 1;
        }
    }
    control.publish_apic(apic);
    if core.pending().is_none() && core.cpu().flags & 0x200 != 0 && !core.shadow() {
        if apic.interrupts.irr.words.iter().any(|&word| word != 0) {
            if let Some(vector) = apic.candidate() {
                match core.inject(vector) {
                    Injection::Queued => state.apic_offer = Some(vector),
                    other => return Err(Error::Injection(other)),
                }
            }
        }
    }
    clock.cancel_timeout();
    if apic.enabled() && apic.lvt[0] & 0x10000 == 0 && core.cpu().flags & 0x200 != 0 {
        match apic.timer.deadline() {
            Deadline::Stopped => {}
            Deadline::At(value) => {
                let time = value / TICKS_PER_100NS + u64::from(value % TICKS_PER_100NS != 0);
                clock.set_timeout(vmcore::vmtime::VmTime::from_100ns(time));
            }
            Deadline::BeyondClock => return Err(Error::Profile("APIC deadline exceeds its clock")),
        }
    }
    Ok(())
}

pub(super) fn acknowledge(
    apic: &mut Option<LocalApic>,
    offer: &mut Option<u8>,
    core: &SharedEventMachine,
) -> Result<Option<u8>, Error> {
    if let Some(vector) = *offer {
        // The core clears pending only after completing this external event's frame.
        // Exceptions retain it, so exception delivery cannot acknowledge this offer.
        if core.pending().is_none() {
            let current = apic.as_mut().ok_or(Error::Completion)?;
            *current = current.accept(vector, true).map_err(Error::ApicIngress)?;
            *offer = None;
            return Ok(Some(vector));
        }
    }
    Ok(None)
}

pub(super) fn control(
    apic: &mut LocalApic,
    access: ControlAccess,
    now: u64,
    ingress: &Control,
    dev: &impl CpuIo,
) -> Result<ControlReply, Error> {
    *apic = apic.advance(now).map_err(Error::Apic)?;
    let operation = match access {
        ControlAccess::ReadMsr(0x1b) => return Ok(ControlReply::Value(apic.base)),
        ControlAccess::ReadMsr(number) => match apic.msr_read(number, now) {
            Ok((next, value)) => {
                *apic = next;
                return Ok(ControlReply::Value(value));
            }
            Err(error) => Err(error),
        },
        ControlAccess::WriteMsr {
            number: 0x1b,
            value,
        } => apic.write_base(value).map(|next| (next, Effect::None)),
        ControlAccess::WriteMsr { number, value } => apic.msr_write(number, value, now),
        ControlAccess::ReadPriority(_) => return Ok(ControlReply::Value(u64::from(apic.tpr >> 4))),
        ControlAccess::WritePriority(value) => {
            apic.write_cr8(value).map(|next| (next, Effect::None))
        }
    };
    match operation {
        Ok((next, effects)) => {
            *apic = next;
            effect(apic, ingress, effects, dev)?;
            Ok(ControlReply::Written)
        }
        Err(ApicError::GeneralProtection) => Ok(ControlReply::GeneralProtection),
        Err(error) => Err(Error::Apic(error)),
    }
}
