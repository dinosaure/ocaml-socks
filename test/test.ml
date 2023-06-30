open OUnit2

(** TODO: OUnit2 should detect test suites automatically. *)
let all_suites =
  [
    "OUnit tests" >::: TestSocks4.suite
  ; "SOCKS 4A QCheck tests" >::: Test_quickcheck_socks4.suite
  ; "SOCKS 5  QCheck tests" >::: Test_socks5.suite
  ]

let () = run_test_tt_main ("all" >::: all_suites)
