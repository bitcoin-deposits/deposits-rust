//! DEP-06 Phase 4 step 3 (strict-lottery-v8, ruled 2026-11-07): a re-arm
//! round's arm windows recur while its lottery output is unspent, against the
//! shared vector `rearm_windows.json` that cl-deposits generates
//! (inspect/gen-rearm-windows.lisp). A window's cut is non-empty iff one of
//! the case's eligible arm heights lies in it.

use deposits_core::tapscript_reserves::{
    rearm_next_window, rearm_open_window, rearm_period, rearm_round_opens, rearm_round_window,
    rearm_window_nth,
};
use serde_json::Value;

fn triple(v: &Value) -> Option<(u32, u32, u32)> {
    let a = v.as_array()?;
    Some((
        a[0].as_u64().unwrap() as u32,
        a[1].as_u64().unwrap() as u32,
        a[2].as_u64().unwrap() as u32,
    ))
}

#[test]
fn rearm_windows_match_the_shared_vector() {
    let v: Value = serde_json::from_str(include_str!("vectors/rearm_windows.json")).unwrap();
    let cases = v["cases"].as_array().unwrap();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let n = |k: &str| c[k].as_u64().unwrap() as u32;
        let (h_l, w, tip) = (n("h_l"), n("w"), n("tip"));
        let arms: Vec<u32> = c["arms"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_u64().unwrap() as u32)
            .collect();
        let o = rearm_round_opens(h_l, c["revealed"].as_bool().unwrap());
        assert_eq!(o, n("opens"), "{name}: opens");
        assert_eq!(rearm_period(w), n("period"), "{name}: period");
        let windows: Vec<(u32, u32)> = c["windows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| {
                let a = x.as_array().unwrap();
                (a[0].as_u64().unwrap() as u32, a[1].as_u64().unwrap() as u32)
            })
            .collect();
        let ours: Vec<(u32, u32)> = (0..6).map(|j| rearm_window_nth(o, w, j)).collect();
        assert_eq!(ours, windows, "{name}: windows");
        let nonempty = |op: u32, cl: u32| arms.iter().any(|&a| op < a && a <= cl);
        assert_eq!(
            rearm_round_window(o, w, tip, nonempty),
            triple(&c["round_window"]),
            "{name}: round window"
        );
        assert_eq!(
            rearm_open_window(o, w, tip),
            triple(&c["open"]),
            "{name}: open window"
        );
        assert_eq!(
            rearm_next_window(o, w, tip),
            n("next_opens"),
            "{name}: next window"
        );
    }
    assert_eq!(cases.len(), 11, "every rearm_windows case ran");
}
