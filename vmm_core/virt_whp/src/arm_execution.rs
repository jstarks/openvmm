// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::Context;
use virt::aarch64::BackendExecutionState;
use whp::Processor;
use whp::abi::*;

const VP_FORMAT: &str = "whp-arm64-vp/1";
const VM_FORMAT: &str = "whp-arm64-gicd/1";

fn registers() -> Vec<WHV_REGISTER_NAME> {
    let mut regs: Vec<_> = (WHvArm64RegisterQ0.0..=WHvArm64RegisterQ31.0)
        .map(WHV_REGISTER_NAME)
        .collect();
    regs.extend([
        WHvArm64RegisterFpcr,
        WHvArm64RegisterFpsr,
        WHvArm64RegisterCpacrEl1,
        WHvArm64RegisterSpsrEl1,
        WHvArm64RegisterTpidrEl0,
        WHvArm64RegisterTpidrEl1,
        WHvArm64RegisterTpidrroEl0,
        WHvArm64RegisterContextidrEl1,
        WHvArm64RegisterParEl1,
        WHvArm64RegisterCntkctlEl1,
        WHvArm64RegisterCntvctEl0,
        WHvArm64RegisterCntvCvalEl0,
        WHvArm64RegisterCntvCtlEl0,
        WHvArm64RegisterApiAKeyLoEl1,
        WHvArm64RegisterApiAKeyHiEl1,
        WHvArm64RegisterApiBKeyLoEl1,
        WHvArm64RegisterApiBKeyHiEl1,
        WHvArm64RegisterApdAKeyLoEl1,
        WHvArm64RegisterApdAKeyHiEl1,
        WHvArm64RegisterApdBKeyLoEl1,
        WHvArm64RegisterApdBKeyHiEl1,
        WHvArm64RegisterApgAKeyLoEl1,
        WHvArm64RegisterApgAKeyHiEl1,
    ]);
    regs
}

fn interrupt_state(
    vp: Processor<'_>,
    ty: WHV_VIRTUAL_PROCESSOR_STATE_TYPE,
) -> anyhow::Result<Vec<u8>> {
    // Global state contains at most 1024 16-byte interrupt entries and
    // a header; the local redistributor record is smaller.
    let mut bytes = vec![0; 5 * 4096];
    let n = vp
        .get_state(ty, &mut bytes)
        .context("saving ARM interrupt controller")?;
    anyhow::ensure!(
        n > 0 && n <= bytes.len(),
        "invalid WHP interrupt state size {n}"
    );
    bytes.truncate(n);
    Ok(bytes)
}

pub fn save_vm(vp: Processor<'_>) -> anyhow::Result<Option<BackendExecutionState>> {
    Ok(Some(BackendExecutionState {
        format: VM_FORMAT.into(),
        data: interrupt_state(vp, WHvVirtualProcessorStateTypeArmGlobalInterrupt)?,
    }))
}

pub fn restore_vm(vp: Processor<'_>, state: Option<&BackendExecutionState>) -> anyhow::Result<()> {
    let state = state.context("missing ARM WHP global execution state")?;
    anyhow::ensure!(
        state.format == VM_FORMAT && state.data.len() <= 5 * 4096,
        "invalid ARM WHP global execution state"
    );
    vp.set_state(WHvVirtualProcessorStateTypeArmGlobalInterrupt, &state.data)
        .context("restoring ARM distributor")
}

pub fn save_vp(vp: Processor<'_>) -> anyhow::Result<Option<BackendExecutionState>> {
    let regs = registers();
    let mut values = vec![WHV_REGISTER_VALUE::default(); regs.len()];
    vp.get_registers(&regs, &mut values)
        .context("saving ARM execution registers")?;
    let mut data = Vec::new();
    for v in values {
        data.extend_from_slice(&u128::from(v.0).to_le_bytes());
    }
    data.extend(interrupt_state(
        vp,
        WHvVirtualProcessorStateTypeArmLocalInterrupt,
    )?);
    Ok(Some(BackendExecutionState {
        format: VP_FORMAT.into(),
        data,
    }))
}

pub fn restore_vp(vp: Processor<'_>, state: Option<&BackendExecutionState>) -> anyhow::Result<()> {
    let state = state.context("missing ARM WHP processor execution state")?;
    let regs = registers();
    let n = regs.len() * 16;
    anyhow::ensure!(
        state.format == VP_FORMAT && state.data.len() > n && state.data.len() <= n + 5 * 4096,
        "invalid ARM WHP processor execution state"
    );
    let (bytes, local) = state.data.split_at(n);
    vp.set_state(WHvVirtualProcessorStateTypeArmLocalInterrupt, local)
        .context("restoring ARM redistributor")?;
    let values: Vec<_> = bytes
        .chunks_exact(16)
        .map(|b| WHV_REGISTER_VALUE(u128::from_le_bytes(b.try_into().unwrap()).into()))
        .collect();
    vp.set_registers(&regs, &values)
        .context("restoring ARM execution registers")
}
