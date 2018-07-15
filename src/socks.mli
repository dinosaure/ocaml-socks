(** Parsing and generation of SOCKS client/server messages *)

open Socks_types

(** This library implements functions for parsing and generating
    the packets required to establish connections using
    SOCKS CONNECT (versions 4{_ A} and 5).

    The parsing functions prefixed with [parse_] return unconsumed bytes
    in a [type Socks_types.leftover_bytes = string].

    This version of the library does not handle BIND and UDP methods since
    I haven't seen that in use anywhere).

    To learn about the flow/order of functions to use,
    see the {{:#examples} examples section}.

    If you're writing a client or server with [Lwt], consider looking at the
    [Socks_lwt] documentation.
*)

(** {2:general General functions} *)

val parse_request : string -> request_result
(** [parse_request buf] is [buf] parsed as a request (either a SOCKS 4{_ A}
    CONNECT request or a SOCKS 5 method authentication selection request).
*)

(** {2:socks4a_specific Functions specific to SOCKS 4{_ A}} *)

val make_socks4_request : username:string -> hostname:string -> int ->
  (string, request_invalid_argument) result
(** [make_socks4_request ~username ~hostname port] returns a binary string
    which represents a SOCKS 4{_ A} request.
    The SOCKS 4{_ A} protocol does not support password authentication.
*)

val make_socks4_response : success:bool -> string
(** [make_response success] returns a binary string which represents a granted
    or rejected response. *)

val parse_socks4_response : string -> (leftover_bytes,
                                       socks4_response_error) Result.result
(** [parse_response result] returns an OK [Result.result] with a unit value on
    success, and a [Rejected] on failure. Bad values return an
    [Incomplete_response]. *)

(** {2:socks5_specific Functions specific to SOCKS 5} *)

val make_socks5_auth_request : username_password:bool -> string
(** [make_socks5_auth_request ~username_password] returns a binary
    string which represents a SOCKS 5 authentication request.
    In the protocol this is a list of authentication modes that the client is
    willing to use, but in our API it's a choice between "no auth methods"
    and "username/password".

    This library only supports "no auth" and "username/password" authentication.
*)

(** [parse_socks5_auth_request data] is contained within [parse_request]
*)

val make_socks5_username_password_request :
  username:string -> password:string -> (string,unit) Result.result
(** [make_socks5_username_password_request ~username ~password] returns a
    binary string which represents a SOCKS 5 password request from [RFC1929].
    The function fails if either of the strings are longer than 255 bytes,
    or are empty.
*)

val parse_socks5_username_password_request :
  string -> socks5_username_password_request_parse_result
(** [parse_socks5_username_password_request buf] parses the given [buf] and
    returns either an [Incomplete_request] or a
    [socks5_username_password_request_parse_result]. *)

val make_socks5_username_password_response : accepted:bool -> string
(** Sent by the server in response to receiving a message from the client
    parsed with {!parse_socks5_username_password_request}.*)

val parse_socks5_username_password_response : string ->
  (bool * leftover_bytes, [`Incomplete_request | `Invalid_request]) result
(** Used by the client to parse a {!make_socks5_username_password_response}
    received from the server.
    [true] if the user/pw combination was accepted by the server and the
    connection should continue,
    [false] if not.*)

val socks5_authentication_method_of_char : char -> socks5_authentication_method
(** [socks5_authentication_method_of_char char] is a conversion function which
    translates the given character to a [socks5_authentication_method]
    value. If no matches were found, the value is [No_acceptable_methods]. *)

val make_socks5_auth_response : socks5_authentication_method -> string
(** [make_socks5_auth_response auth_method] returns a binary string which
    represents a SOCKS 5 authentication response explaining which authentication
    method the server wants the client to use.
*)

val make_socks5_request : socks5_request ->
  (string, request_invalid_argument) Result.result
(** [make_socks5_request (Connect|Bind {address; port}) ]
    returns a binary string which represents a SOCKS 5 request as described in
    RFC 1928 section "4. Requests" (on page 3).
    For DOMAINNAME addresses the length of the domain must be 1..255
*)

val parse_socks5_connect :
  string ->
  (socks5_struct * leftover_bytes,
   [> `Invalid_request | `Incomplete_request ])
  Result.result
(** [parse_socks5_connect buf] returns an OK result with port and hostname
    if [buf] represents a SOCKS 5 CONNECT command with the DOMAINNAME form.
    If anything is amiss, it will return [R.error] values, wrapping
    [Invalid_argument], [Invalid_request] and [Incomplete_request]. *)

val make_socks5_response : socks5_reply_field -> bnd_port:int ->
  socks5_address -> (string, Rresult.R.msg) result
(** [make_socks5_response reply_field ~bnd_port address] returns a binary string
    which represents the response to a
    SOCKS 5 action (CONNECT|BIND|UDP_ASSOCIATE).
    NB that for e.g. BIND you will need to send several of these.
    TODO reference RFC section.
*)

val parse_socks5_response : string ->
  (socks5_reply_field * socks5_struct * leftover_bytes,
   socks5_response_error) result
(** [parse_response response_string]
  TODO document. But basically it returns the error code (if any),
    and the remote bound address/port info from the server.
*)


(** {1:examples Examples} *)

(** Take care to pass the [leftover] strings into the next parsing function,
    and, when you're done parsing, to the client.*)

(** {2:example_socks4_only_server SOCKS 4{_ A}-only server} *)

(** To handle a client connection, the state machine required is:
    {ol
      {- [let Socks4_request (request, leftover) = ]{!parse_request}
        {ul
          {- if the pattern matching failed,
             send {!make_socks4_response}[ ~success:false] {b and abort}.}
        }
      }
      {- send {!make_socks4_response}[ ~success:true]}
      {- forward traffic between client and server.}
    }
*)

(** {2:example_socks5_only_server SOCKS 5-only server} *)

(* TODO the indentation is not really reflected properly in the code below: *)
(** To handle a client connection, the state machine required is:
    {ol
    {- [let Socks5_method_selection_request
       (_::_ as method_request, leftover) = ]{!parse_request}
       {ul {- if pattern matching failed,
              send {!make_socks5_auth_response}[ No_acceptable_methods.
]
              Unfortunately RFC 1928 does not define any other way to signal
              to the client that parsing the authentication request failed.}
       }
    }
    {- [let auth_method = (*pick an authentication method from*) method_request
] and send {!make_socks5_auth_response}[ auth_method].}
    {- [if auth_method = Username_password ("","")]
      {ul
        {- [then let Username_password (username,password,leftover) =
             ]{!parse_socks5_username_password_request}
          {ul
            {- if you accept the credentials, send:
              {!make_socks5_username_password_response}[ ~accepted:true]}
            {- else send {!make_socks5_username_password_response}
            [ ~accepted:false
    ] {b and abort}.}
          }
        }
      }
    }
    {- [let Ok (request,leftover) = ]{!parse_socks5_connect}
       {ul
         {- if pattern matching failed, send
           {!make_socks5_response}[ General_socks_server_failure
    ] {b and abort}.}
       }
    }
    {- if [request] is not allowed according to your policy, send
      {!make_socks5_response}[ Connection_not_allowed_by_ruleset
    ] {b and abort}.}
    {- try to make the connection to the target}
    {- if the connection cannot be established, send
      {!make_socks5_response}[ Host_unreachable] {b and abort}.[
]     (you can of course use a more precise error code if you so desire).}
    {- send {!make_socks5_response}[ Succeeded] and start forwarding traffic.}
    }
*)
