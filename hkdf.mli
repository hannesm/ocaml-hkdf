
(** {{:https://tools.ietf.org/html/rfc5869}RFC 5869} specifies a HMAC-based
    Extract-and-Expand Key Derivation Function (HKDF), which is abstracted over
    a specific hash function. *)

module type S = sig

  (** [extract salt ikm] is [prk], the pseudorandom key of hash length octets.
      The [salt] is an optional non-secret random value, [ikm] the input key
      material. *)
  val extract : ?salt:string -> string -> string

  (** [extract prk info length] is [okm], the output keying material.  Given the
  pseudorandom key of hash length (usually output of [!extract] step), and an
  optional context and application specific information [info], the [okm] is
  generated. *)
  val expand : prk:string -> ?info:string -> int -> string
end

(** Given a Hash function, get the HKDF *)
module Make (H : Digestif.S) : S

(** convenience [extract hash salt ikm] where the [hash] has to be provided explicitly *)
val extract : hash:Digestif.hash' -> ?salt:string -> string -> string

(** convenience [expand hash prk info len] where the [hash] has to be provided explicitly *)
val expand : hash:Digestif.hash' -> prk:string -> ?info:string -> int -> string
