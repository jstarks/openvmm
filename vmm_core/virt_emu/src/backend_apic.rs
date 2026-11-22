// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use strudel::LapicAccess;
use x86_system::arch::apic::{
    registers::{Effect, Error as ApicError},
    route::{FixedIpi, Interface},
    timer::{Deadline, Error as TimerError},
};
use x86_system::execute::control_io::{ControlAccess, ControlReply};

const TICKS_PER_100NS: u64 = 10;

pub(super) fn deadline_time(value: u64) -> vmcore::vmtime::VmTime {
    vmcore::vmtime::VmTime::from_100ns(
        value / TICKS_PER_100NS + u64::from(!value.is_multiple_of(TICKS_PER_100NS)),
    )
}

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
        self.incoming_banks
            .fetch_or(1 << (vector / 32), Ordering::Release);
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
        self.incoming_banks.load(Ordering::Acquire) != 0
    }

    fn drain_apic(&self, apic: &mut LapicAccess<'_>) -> Result<(), Error> {
        // Clear before draining: concurrent publication must leave a notification.
        let banks = self.incoming_banks.swap(0, Ordering::AcqRel);
        for (bank, slot) in self.incoming.iter().enumerate() {
            if banks & (1 << bank) == 0 {
                continue;
            }
            let packet = slot.swap(0, Ordering::AcqRel);
            let mut pending = packet as u32;
            while pending != 0 {
                let bit = pending.trailing_zeros();
                let vector = (bank * 32 + bit as usize) as u8;
                apic.receive(vector, packet & (1u64 << (bit + 32)) != 0)
                    .map_err(Error::ApicIngress)?;
                pending &= pending - 1;
            }
        }
        Ok(())
    }
}

pub(super) fn effect(
    apic: &mut LapicAccess<'_>,
    control: &Control,
    effect: Effect,
    dev: &impl CpuIo,
) -> Result<(), Error> {
    let registers = apic.registers();
    control.publish_apic(registers);
    match effect {
        Effect::None => {}
        Effect::Eoi(eoi) => {
            if eoi.broadcast {
                dev.handle_eoi(u32::from(eoi.vector.ok_or(Error::Completion)?));
            }
        }
        Effect::Ipi(packet) => {
            if packet.targets(
                registers.id,
                registers.id,
                registers.ldr,
                registers.enabled(),
            ) {
                apic.receive(packet.vector, false)
                    .map_err(Error::ApicIngress)?;
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
    let CpuLifecycle::Ready(core) = &mut state.cpu else {
        return Ok(());
    };
    if core.lapic_offer().is_some() || !core.at_interrupt_boundary() {
        return Ok(());
    }
    // APIC register accesses materialize the counter themselves. With IF clear,
    // defer timer-only work until it can affect entry, observation, or a wait.
    if !core.physical_interrupts_enabled() && !core.halted() && !control.apic_work_pending() {
        return Ok(());
    }
    let enabled = core.physical_interrupts_enabled();
    let Some(mut apic) = core.lapic_access() else {
        return Ok(());
    };
    let now = ticks(clock.now())?;
    if now < apic.registers().timer.last {
        return Err(Error::Apic(ApicError::Timer(TimerError::BackwardsTime)));
    }
    // Counter reads/writes materialize time themselves. Between deadlines,
    // no timer effect is observable and the absolute deadline is unchanged.
    if matches!(apic.registers().timer.deadline(),Deadline::At(deadline) if now>=deadline) {
        apic.advance(now).map_err(Error::Apic)?;
    }
    control.drain_apic(&mut apic)?;
    let apic = apic.registers();
    control.publish_apic(apic);
    clock.cancel_timeout();
    if apic.enabled() && apic.lvt[0] & 0x10000 == 0 && enabled {
        match apic.timer.deadline() {
            Deadline::Stopped => {}
            Deadline::At(value) => {
                clock.set_timeout(deadline_time(value));
            }
            Deadline::BeyondClock => return Err(Error::Profile("APIC deadline exceeds its clock")),
        }
    }
    Ok(())
}

pub(super) fn control(
    apic: &mut LapicAccess<'_>,
    access: ControlAccess,
    now: u64,
    ingress: &Control,
    dev: &impl CpuIo,
) -> Result<ControlReply, Error> {
    let operation = match access {
        ControlAccess::ReadMsr(number) => match apic.msr_read(number, now) {
            Ok(value) => return Ok(ControlReply::Value(value)),
            Err(error) => Err(error),
        },
        ControlAccess::WriteMsr { number, value } => apic.msr_write(number, value, now),
    };
    match operation {
        Ok(effects) => {
            effect(apic, ingress, effects, dev)?;
            Ok(ControlReply::Written)
        }
        Err(ApicError::GeneralProtection) => Ok(ControlReply::GeneralProtection),
        Err(error) => Err(Error::Apic(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn concurrent_mailbox_publication_and_drain_preserve_every_request() {
        let control = Control::new(true);
        let acknowledged = AtomicUsize::new(0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut apic = LocalApic::new(0, true, 0);
        apic.svr = 0x1ff;
        std::thread::scope(|scope| {
            let producer = scope.spawn(|| {
                for round in 0..10_000usize {
                    control.post_apic((64 + round % 192) as u8, round % 2 == 0);
                    while acknowledged.load(Ordering::Acquire) <= round {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "mailbox request was lost"
                        );
                        std::thread::yield_now();
                    }
                }
            });
            for round in 0..10_000usize {
                let vector = 64 + round % 192;
                let bank = vector / 32;
                let mask = 1u32 << (vector % 32);
                loop {
                    control
                        .drain_apic(&mut LapicAccess::new(&mut apic))
                        .unwrap();
                    if apic.interrupts.irr.words[bank] & mask != 0 {
                        break;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "mailbox request was lost"
                    );
                    std::hint::spin_loop();
                }
                assert_eq!(apic.interrupts.tmr.words[bank] & mask != 0, round % 2 == 0);
                apic.interrupts.irr.words[bank] &= !mask;
                acknowledged.store(round + 1, Ordering::Release);
            }
            producer.join().unwrap();
        });
        control
            .drain_apic(&mut LapicAccess::new(&mut apic))
            .unwrap();
        assert!(!control.apic_work_pending());
        assert!(
            control
                .incoming
                .iter()
                .all(|slot| slot.load(Ordering::Acquire) == 0)
        );
    }
}
