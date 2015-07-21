%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  20 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(crypto_rsassa_pss).

-include_lib("public_key/include/public_key.hrl").

%% API
-export([sign/3]).
-export([sign/4]).
-export([verify/4]).

%% Types
-type rsa_public_key()  :: #'RSAPublicKey'{}.
-type rsa_private_key() :: #'RSAPrivateKey'{}.
-type rsa_digest_type() :: 'md5' | 'sha'| 'sha224' | 'sha256' | 'sha384' | 'sha512'.

-define(PSS_TRAILER_FIELD, 16#BC).

%%====================================================================
%% API functions
%%====================================================================

-spec sign(Message, DigestType, PrivateKey) -> Signature
	when
		Message    :: binary() | {digest, binary()},
		DigestType :: rsa_digest_type() | atom(),
		PrivateKey :: rsa_private_key(),
		Signature  :: binary().
sign(Message, DigestType, PrivateKey) when is_binary(Message) ->
	sign({digest, crypto:hash(DigestType, Message)}, DigestType, PrivateKey);
sign(Message={digest, _}, DigestType, PrivateKey) ->
	SaltLen = byte_size(crypto:hash(DigestType, <<>>)),
	Salt = crypto:rand_bytes(SaltLen),
	sign(Message, DigestType, Salt, PrivateKey).

-spec sign(Message, DigestType, Salt, PrivateKey) -> Signature
	when
		Message    :: binary() | {digest, binary()},
		DigestType :: rsa_digest_type() | atom(),
		Salt       :: binary(),
		PrivateKey :: rsa_private_key(),
		Signature  :: binary().
sign(Message, DigestType, Salt, PrivateKey) when is_binary(Message) ->
	sign({digest, crypto:hash(DigestType, Message)}, DigestType, Salt, PrivateKey);
sign({digest, Digest}, DigestType, Salt, PrivateKey=#'RSAPrivateKey'{modulus=N}) ->
	DigestLen = byte_size(Digest),
	SaltLen = byte_size(Salt),
	PrivateSize = byte_size(binary:encode_unsigned(N)),
	case PrivateSize < (DigestLen + SaltLen + 2) of
		false ->
			PublicBits = PrivateSize * 8,
			DBLen = PrivateSize - DigestLen - 1,
			M = << 0:64, Digest/binary, Salt/binary >>,
			H = crypto:hash(DigestType, M),
			DB = << 0:((DBLen - SaltLen - 1) * 8), 1, Salt/binary >>,
			DBMask = mgf1(DigestType, H, DBLen),
			MaskedDB = normalize_to_key_size(PublicBits, crypto:exor(DB, DBMask)),
			EM = << MaskedDB/binary, H/binary, ?PSS_TRAILER_FIELD >>,
			dp(EM, PrivateKey);
		true ->
			erlang:error(badarg, [{digest, Digest}, DigestType, Salt, PrivateKey])
	end.

-spec verify(Message, DigestType, Signature, PublicKey) -> boolean()
	when
		Message    :: binary() | {digest, binary()},
		DigestType :: rsa_digest_type() | atom(),
		Signature  :: binary(),
		PublicKey  :: rsa_public_key().
verify(Message, DigestType, Signature, PublicKey) when is_binary(Message) ->
	verify({digest, crypto:hash(DigestType, Message)}, DigestType, Signature, PublicKey);
verify({digest, Digest}, DigestType, Signature, PublicKey=#'RSAPublicKey'{modulus=N}) ->
	DigestLen = byte_size(Digest),
	PublicSize = byte_size(binary:encode_unsigned(N)),
	SignatureSize = byte_size(Signature),
	case PublicSize =:= SignatureSize of
		true ->
			PublicBits = PublicSize * 8,
			DBLen = PublicSize - DigestLen - 1,
			EM = ep(Signature, PublicKey),
			case binary:last(EM) of
				?PSS_TRAILER_FIELD ->
					MaskedDB = binary:part(EM, 0, byte_size(EM) - DigestLen - 1),
					H = binary:part(EM, byte_size(MaskedDB), DigestLen),
					DBMask = mgf1(DigestType, H, DBLen),
					DB = normalize_to_key_size(PublicBits, crypto:exor(MaskedDB, DBMask)),
					case binary:match(DB, << 1 >>) of
						{Pos, Len} ->
							PS = binary:decode_unsigned(binary:part(DB, 0, Pos)),
							case PS =:= 0 of
								true ->
									Salt = binary:part(DB, Pos + Len, byte_size(DB) - Pos - Len),
									M = << 0:64, Digest/binary, Salt/binary >>,
									HOther = crypto:hash(DigestType, M),
									H =:= HOther;
								false ->
									false
							end;
						nomatch ->
							false
					end;
				_ ->
					false
			end;
		false ->
			false
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
dp(B, #'RSAPrivateKey'{modulus=N, privateExponent=E}) ->
	crypto:mod_pow(B, E, N).

%% @private
ep(B, #'RSAPublicKey'{modulus=N, publicExponent=E}) ->
	crypto:mod_pow(B, E, N).

%% @private
mgf1(DigestType, Seed, Len) ->
	mgf1(DigestType, Seed, Len, <<>>, 0).

%% @private
mgf1(_DigestType, _Seed, Len, T, _Counter) when byte_size(T) >= Len ->
	binary:part(T, 0, Len);
mgf1(DigestType, Seed, Len, T, Counter) ->
	CounterBin = << Counter:8/unsigned-big-integer-unit:4 >>,
	NewT = << T/binary, (crypto:hash(DigestType, << Seed/binary, CounterBin/binary >>))/binary >>,
	mgf1(DigestType, Seed, Len, NewT, Counter + 1).

%% @private
normalize_to_key_size(_, <<>>) ->
	<<>>;
normalize_to_key_size(Bits, << C, Rest/binary >>) ->
	SH = (Bits - 1) band 16#7,
	Mask = case SH > 0 of
		false ->
			16#FF;
		true ->
			16#FF bsr (8 - SH)
	end,
	<< (C band Mask), Rest/binary >>.
