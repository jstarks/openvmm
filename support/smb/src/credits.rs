// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded command sequence window: MS-SMB2 §§3.3.1.1, 3.3.1.2, 3.3.5.2.3.

use crate::Error;
use std::collections::BTreeSet;

pub(super) struct Window {
    available: BTreeSet<u64>,
    next: u64,
}

impl Window {
    pub fn new() -> Self {
        Self {
            available: BTreeSet::from([0]),
            next: 1,
        }
    }

    pub fn len(&self) -> u32 {
        self.available.len() as u32
    }

    pub fn consume(&mut self, ranges: &[(u64, u32)]) -> Result<(), Error> {
        let mut available = self.available.clone();
        for &(message, charge) in ranges {
            let end = message
                .checked_add(u64::from(charge))
                .ok_or(Error::InvalidCreditSequence(message))?;
            for id in message..end {
                if !available.remove(&id) {
                    return Err(Error::InvalidCreditSequence(id));
                }
            }
        }
        self.available = available;
        Ok(())
    }

    pub fn grant(&mut self, count: u32) -> Result<u16, Error> {
        let end = self
            .next
            .checked_add(u64::from(count))
            .ok_or(Error::CreditSequenceExhausted)?;
        self.available.extend(self.next..end);
        self.next = end;
        Ok(count as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_with_tracing::test;

    #[test]
    fn ranges_are_atomic_out_of_order_and_never_reissued() {
        let mut window = Window::new();
        window.consume(&[(0, 1)]).unwrap();
        window.grant(4).unwrap();
        window.consume(&[(3, 2)]).unwrap();
        assert!(window.consume(&[(1, 1), (2, 2)]).is_err());
        window.consume(&[(1, 2)]).unwrap();
        window.grant(2).unwrap();
        assert!(window.consume(&[(1, 1)]).is_err());
        window.consume(&[(5, 2)]).unwrap();
        window.next = u64::MAX;
        assert!(matches!(
            window.grant(1),
            Err(Error::CreditSequenceExhausted)
        ));
        assert!(matches!(
            window.consume(&[(u64::MAX, 1)]),
            Err(Error::InvalidCreditSequence(_))
        ));
    }
}
