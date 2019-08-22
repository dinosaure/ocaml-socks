open OUnit2
open Socks
open Rresult

let is_invalid (r : request_result) =
  r = Error `Invalid_request

let is_incomplete (r : request_result) =
  r = Error `Incomplete_request

let is_request = function Ok _ -> true | _ -> false

let test_make_request _ =
  let username = "myusername" in
  let hostname = "example.com" in
  assert_bool "example.com:4321"
    (make_socks4_request ~username ~hostname:"example.com" 4321
    = R.ok @@ "\x04\x01"
    ^ "\x10\xe1" (* port *)
    ^ "\x00\x00\x00\xff"
    ^ username ^ "\x00"
    ^ hostname ^ "\x00")
;;

let test_make_response _ =
  let empty_ip_and_port = "\x00\x00" ^ "\x00\x00\x00\x00" in
  assert_equal (make_socks4_response ~success:true)
  ("\x00\x5a" ^ empty_ip_and_port)
  ;;
  let empty_ip_and_port = "\x00\x00" ^ "\x00\x00\x00\x00" in
  assert_equal (make_socks4_response ~success:false)
  ("\x00\x5b" ^ empty_ip_and_port)
  ;;

let invalid_requests _ =
  assert_bool "invalid protocol" (is_invalid (parse_request "\x00\x001234567")) ;;

let incomplete_requests _ =
  "\x04"
  |> parse_request |> is_incomplete |> assert_bool
  "8 bytes" ;;

let requests _ =
  let r = make_socks4_request ~username:"user" ~hostname:"host" 515 in
  begin match r with
  | Ok r ->
    begin match parse_request (r ^ "X") with
    | Ok Socks4_request (pr , "X") ->
      (   pr.port     = 515
       && pr.username = "user"
       && pr.address  = "host")
    | _ -> false
    end
  | Error _ -> false
  end
  |> assert_bool
  "self-check request" ;;

let regression_00 _ =
  begin match Socks.parse_request "\004\001\000P\172\217\021\142yo\000" with
  | Ok Socks4_request _ -> true
  | _ -> false end
  |> assert_bool "handling empty leftover in parse_request"
;;

(** TODO: OUnit2 should detect test cases automatically. *)
let suite = [
    "make_request" >:: test_make_request;
    "make_response" >:: test_make_response;
    "parse_request: invalid_requests" >:: invalid_requests;
    "parse_request: incomplete_requests" >:: incomplete_requests;
    "is_request" >:: requests;
    "regression 00: parse_request handling empty leftover" >:: regression_00;
  ]
