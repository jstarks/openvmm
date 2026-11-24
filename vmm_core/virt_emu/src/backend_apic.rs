// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use strudel::LapicAccess;
use x86_system::arch::apic::{
    registers::{Effect, Error as ApicError},
    route::{FixedIpi, Interface},
    timer::Deadline,
};
use x86_system::execute::control_io::{ControlAccess, ControlReply};

const TICKS_PER_100NS: u64 = 10;

fn deadline_time(value: u64) -> vmcore::vmtime::VmTime {
    vmcore::vmtime::VmTime::from_100ns(value.div_ceil(TICKS_PER_100NS))
}

pub(super) fn ticks(time: vmcore::vmtime::VmTime) -> Result<u64, Error> {
    time.as_100ns()
        .checked_mul(TICKS_PER_100NS)
        .ok_or(Error::Profile("APIC base-clock counter exhausted"))
}

impl Control {
    pub(super) fn publish_apic(&self, apic: &LocalApic) {
        let mask = if apic.enabled() { 0 } else { 1 << 16 };
        self.lint_routes.store(
            u64::from(apic.lvt[3] | mask) | (u64::from(apic.lvt[4] | mask) << 32),
            Ordering::Release,
        );
        self.routing.store(
            u64::from(apic.id) | (u64::from(apic.ldr) << 32) | (u64::from(apic.enabled()) << 40),
            Ordering::Release,
        );
    }

    pub(super) fn request_apic_msi(&self, request: virt::irqcon::MsiRequest) {
        if !self.has_apic || request.address >> 20 != 0xfee {
            self.unsupported();
            return;
        }
        let (address, data) = request.as_x86();
        if data.delivery_mode() > 1 {
            self.unsupported();
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
            if packet.vector < 32 {
                self.unsupported();
            } else {
                self.remote
                    .post_interrupt(packet.vector, data.trigger_mode_level());
            }
        }
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

/// Register directly with the VM-time producer. It signals the run control
/// independently of the thread currently executing or sleeping in the VP.
pub(super) fn arm_timer(
    deadline: Deadline,
    clock: &mut VmTimeAccess,
    timer: &Arc<TimerWake>,
    rearm: bool,
) -> Result<(), Error> {
    let deadline = match deadline {
        Deadline::Stopped => None,
        Deadline::At(value) => Some(deadline_time(value)),
        Deadline::BeyondClock => return Err(Error::Profile("APIC deadline exceeds its clock")),
    };
    if !rearm && clock.get_timeout() == deadline {
        return Ok(());
    }
    if let Some(deadline) = deadline {
        clock.set_timeout(deadline);
        let wake = Waker::from(timer.clone());
        if clock
            .poll_timeout(&mut Context::from_waker(&wake))
            .is_ready()
        {
            wake.wake();
        }
    } else {
        clock.cancel_timeout();
    }
    Ok(())
}

pub(super) fn expire_timer(
    core: &mut Machine,
    clock: &mut VmTimeAccess,
    timer: &Arc<TimerWake>,
) -> Result<(), Error> {
    let Some(mut apic) = core.lapic_access() else {
        return Ok(());
    };
    apic.advance(ticks(clock.now())?).map_err(Error::Apic)?;
    arm_timer(apic.timer_deadline(), clock, timer, true)
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
