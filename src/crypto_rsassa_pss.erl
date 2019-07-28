%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2019, Andrew Bennett
%%% @doc PKCS #1: RSA Cryptography Specifications Version 2.1
%%% See RFC 3447: [https://tools.ietf.org/html/rfc3447]
%%% @end
%%% Created :  20 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(crypto_rsassa_pss).

-include_lib("public_key/include/public_key.hrl").

%% Public API
-export([sign/3]).
-export([sign/4]).
-export([verify/4]).
-export([verify/5]).
%% Private API
-export([emsa_pss_encode/3]).
-export([emsa_pss_encode/4]).
-export([emsa_pss_verify/4]).
-export([emsa_pss_verify/5]).
-export([mgf1/3]).
-export([rsassa_pss_sign/3]).
-export([rsassa_pss_sign/4]).
-export([rsassa_pss_verify/4]).
-export([rsassa_pss_verify/5]).

%% Types
-type rsa_digest_type() :: 'md5' | 'sha' | 'sha224' | 'sha256' | 'sha384' | 'sha512'.
-type rsa_hash_fun()    :: rsa_digest_type() | {hmac, rsa_digest_type(), iodata()} | fun((iodata()) -> binary()).
-type rsa_public_key()  :: #'RSAPublicKey'{}.
-type rsa_private_key() :: #'RSAPrivateKey'{}.

-define(PSS_TRAILER_FIELD, 16#BC).

%%====================================================================
%% Public API functions
%%====================================================================

-spec sign(Message, DigestType, RSAPrivateKey) -> Signature
	when
		Message       :: binary(),
		DigestType    :: rsa_digest_type(),
		RSAPrivateKey :: rsa_private_key(),
		Signature     :: binary().
sign(Message, DigestType, PrivateKey) ->
	sign(Message, DigestType, -2, PrivateKey).

-spec sign(Message, DigestType, Salt, RSAPrivateKey) -> Signature
	when
		Message       :: binary(),
		DigestType    :: rsa_digest_type(),
		Salt          :: integer() | binary(),
		RSAPrivateKey :: rsa_private_key(),
		Signature     :: binary().
sign(Message, DigestType, Salt, PrivateKey=#'RSAPrivateKey'{}) ->
	case rsassa_pss_sign(DigestType, Message, Salt, PrivateKey) of
		{ok, Signature} ->
			Signature;
		{error, Reason} ->
			erlang:error(Reason)
	end;
sign(Message, DigestType, Salt, PrivateKey) ->
	erlang:error(badarg, [Message, DigestType, Salt, PrivateKey]).

-spec verify(Message, DigestType, Signature, RSAPublicKey) -> boolean()
	when
		Message      :: binary(),
		DigestType   :: rsa_digest_type(),
		Signature    :: binary(),
		RSAPublicKey :: rsa_public_key().
verify(Message, DigestType, Signature, PublicKey) ->
	verify(Message, DigestType, Signature, -2, PublicKey).

-spec verify(Message, DigestType, Signature, Salt, RSAPublicKey) -> boolean()
	when
		Message      :: binary(),
		DigestType   :: rsa_digest_type(),
		Signature    :: binary(),
		Salt         :: integer() | binary(),
		RSAPublicKey :: rsa_public_key().
verify(Message, DigestType, Signature, Salt, PublicKey=#'RSAPublicKey'{}) ->
	rsassa_pss_verify(DigestType, Message, Signature, Salt, PublicKey);
verify(Message, DigestType, Signature, Salt, PublicKey) ->
	erlang:error(badarg, [Message, DigestType, Signature, Salt, PublicKey]).

%%====================================================================
%% Private API functions
%%====================================================================

%% See [https://tools.ietf.org/html/rfc3447#section-9.1.1]
-spec emsa_pss_encode(Hash, Message, EMBits) -> {ok, EM} | {error, Reason}
	when
		Hash    :: rsa_hash_fun(),
		Message :: binary(),
		EMBits  :: integer(),
		EM      :: binary(),
		Reason  :: term().
emsa_pss_encode(Hash, Message, EMBits)
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_integer(EMBits) ->
	emsa_pss_encode(Hash, Message, -2, EMBits);
emsa_pss_encode(Hash, Message, EMBits)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	emsa_pss_encode(HashFun, Message, EMBits).

%% See [https://tools.ietf.org/html/rfc3447#section-9.1.1]
-spec emsa_pss_encode(Hash, Message, Salt, EMBits) -> {ok, EM} | {error, Reason}
	when
		Hash    :: rsa_hash_fun(),
		Message :: binary(),
		Salt    :: binary() | integer(),
		EMBits  :: integer(),
		EM      :: binary(),
		Reason  :: term().
emsa_pss_encode(Hash, Message, Salt, EMBits)
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_binary(Salt)
		andalso is_integer(EMBits) ->
	MHash = Hash(Message),
	HashLen = byte_size(MHash),
	SaltLen = byte_size(Salt),
	EMLen = ceiling(EMBits / 8),
	case EMLen < (HashLen + SaltLen + 2) of
		false ->
			MPrime = << 0:64, MHash/binary, Salt/binary >>,
			H = Hash(MPrime),
			PS = << 0:((EMLen - SaltLen - HashLen - 2) * 8) >>,
			DB = << PS/binary, 16#01, Salt/binary >>,
			case mgf1(Hash, H, EMLen - HashLen - 1) of
				{ok, DBMask} ->
					LeftBits = (EMLen * 8) - EMBits,
					<< _:LeftBits/bitstring, MaskedDBRight/bitstring >> = crypto:exor(DB, DBMask),
					MaskedDB = << 0:LeftBits, MaskedDBRight/bitstring >>,
					EM = << MaskedDB/binary, H/binary, ?PSS_TRAILER_FIELD >>,
					{ok, EM};
				MGF1Error ->
					MGF1Error
			end;
		true ->
			{error, encoding_error}
	end;
emsa_pss_encode(Hash, Message, -2, EMBits)
		when is_function(Hash, 1)
		andalso is_integer(EMBits) ->
	HashLen = byte_size(Hash(<<>>)),
	EMLen = ceiling(EMBits / 8),
	SaltLen = EMLen - HashLen - 2,
	case SaltLen < 0 of
		false ->
			emsa_pss_encode(Hash, Message, SaltLen, EMBits);
		true ->
			{error, encoding_error}
	end;
emsa_pss_encode(Hash, Message, -1, EMBits)
		when is_function(Hash, 1) ->
	HashLen = byte_size(Hash(<<>>)),
	SaltLen = HashLen,
	emsa_pss_encode(Hash, Message, SaltLen, EMBits);
emsa_pss_encode(Hash, Message, SaltLen, EMBits)
		when is_integer(SaltLen)
		andalso SaltLen >= 0 ->
	Salt = crypto:strong_rand_bytes(SaltLen),
	emsa_pss_encode(Hash, Message, Salt, EMBits);
emsa_pss_encode(Hash, Message, Salt, EMBits)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	emsa_pss_encode(HashFun, Message, Salt, EMBits).

%% See [https://tools.ietf.org/html/rfc3447#section-9.1.2]
-spec emsa_pss_verify(Hash, Message, EM, EMBits) -> boolean()
	when
		Hash    :: rsa_hash_fun(),
		Message :: binary(),
		EM      :: binary(),
		EMBits  :: integer().
emsa_pss_verify(Hash, Message, EM, EMBits)
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_binary(EM)
		andalso is_integer(EMBits) ->
	emsa_pss_verify(Hash, Message, EM, -2, EMBits);
emsa_pss_verify(Hash, Message, EM, EMBits)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	emsa_pss_verify(HashFun, Message, EM, EMBits).

%% See [https://tools.ietf.org/html/rfc3447#section-9.1.2]
-spec emsa_pss_verify(Hash, Message, EM, SaltLen, EMBits) -> boolean()
	when
		Hash    :: rsa_hash_fun(),
		Message :: binary(),
		EM      :: binary(),
		SaltLen :: integer(),
		EMBits  :: integer().
emsa_pss_verify(Hash, Message, EM, SaltLen, EMBits)
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_integer(SaltLen)
		andalso SaltLen >= 0
		andalso is_integer(EMBits) ->
	MHash = Hash(Message),
	HashLen = byte_size(MHash),
	EMLen = ceiling(EMBits / 8),
	MaskedDBLen = (EMLen - HashLen - 1),
	case {EMLen < (HashLen + SaltLen + 2), byte_size(EM), EM} of
		{false, EMLen, << MaskedDB:MaskedDBLen/binary, H:HashLen/binary, ?PSS_TRAILER_FIELD >>} ->
			LeftBits = ((EMLen * 8) - EMBits),
			case MaskedDB of
				<< 0:LeftBits, _/bitstring >> ->
					case mgf1(Hash, H, EMLen - HashLen - 1) of
						{ok, DBMask} ->
							<< _:LeftBits/bitstring, DBRight/bitstring >> = crypto:exor(MaskedDB, DBMask),
							DB = << 0:LeftBits, DBRight/bitstring >>,
							PSLen = ((EMLen - HashLen - SaltLen - 2) * 8),
							case DB of
								<< 0:PSLen, 16#01, Salt:SaltLen/binary >> ->
									MPrime = << 0:64, MHash/binary, Salt/binary >>,
									HPrime = Hash(MPrime),
									H =:= HPrime;
								_BadDB ->
									false
							end;
						_MGF1Error ->
							false
					end;
				_BadMaskedDB ->
					false
			end;
		_BadEMLen ->
			false
	end;
emsa_pss_verify(Hash, Message, EM, -2, EMBits)
		when is_function(Hash, 1)
		andalso is_integer(EMBits) ->
	HashLen = byte_size(Hash(<<>>)),
	EMLen = ceiling(EMBits / 8),
	SaltLen = EMLen - HashLen - 2,
	case SaltLen < 0 of
		false ->
			emsa_pss_verify(Hash, Message, EM, SaltLen, EMBits);
		true ->
			false
	end;
emsa_pss_verify(Hash, Message, EM, -1, EMBits)
		when is_function(Hash, 1) ->
	HashLen = byte_size(Hash(<<>>)),
	SaltLen = HashLen,
	emsa_pss_verify(Hash, Message, EM, SaltLen, EMBits).

%% See [https://tools.ietf.org/html/rfc3447#appendix-B.2]
-spec mgf1(Hash, Seed, MaskLen) -> {ok, binary()} | {error, mask_too_long}
	when
		Hash    :: rsa_hash_fun(),
		Seed    :: binary(),
		MaskLen :: pos_integer().
mgf1(Hash, Seed, MaskLen)
		when is_function(Hash, 1)
		andalso is_binary(Seed)
		andalso is_integer(MaskLen)
		andalso MaskLen >= 0 ->
	HashLen = byte_size(Hash(<<>>)),
	case MaskLen > (16#FFFFFFFF * HashLen) of
		false ->
			Reps = ceiling(MaskLen / HashLen),
			{ok, derive_mgf1(Hash, 0, Reps, Seed, MaskLen, <<>>)};
		true ->
			{error, mask_too_long}
	end;
mgf1(Hash, Seed, MaskLen)
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	mgf1(HashFun, Seed, MaskLen).

%% See [https://tools.ietf.org/html/rfc3447#section-8.1.1]
-spec rsassa_pss_sign(Hash, Message, RSAPrivateKey) -> {ok, Signature} | {error, Reason}
	when
		Hash          :: rsa_hash_fun(),
		Message       :: binary(),
		RSAPrivateKey :: rsa_private_key(),
		Signature     :: binary(),
		Reason        :: term().
rsassa_pss_sign(Hash, Message, RSAPrivateKey=#'RSAPrivateKey'{modulus=Modulus})
		when is_function(Hash, 1)
		andalso is_binary(Message) ->
	ModBits = int_to_bit_size(Modulus),
	case emsa_pss_encode(Hash, Message, ModBits - 1) of
		{ok, EM} ->
			ModBytes = int_to_byte_size(Modulus),
			S = pad_to_key_size(ModBytes, dp(EM, RSAPrivateKey)),
			{ok, S};
		EncodingError ->
			EncodingError
	end;
rsassa_pss_sign(Hash, Message, RSAPrivateKey=#'RSAPrivateKey'{})
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsassa_pss_sign(HashFun, Message, RSAPrivateKey).

%% See [https://tools.ietf.org/html/rfc3447#section-8.1.1]
-spec rsassa_pss_sign(Hash, Message, Salt, RSAPrivateKey) -> {ok, Signature} | {error, Reason}
	when
		Hash          :: rsa_hash_fun(),
		Message       :: binary(),
		Salt          :: binary() | integer(),
		RSAPrivateKey :: rsa_private_key(),
		Signature     :: binary(),
		Reason        :: term().
rsassa_pss_sign(Hash, Message, Salt, RSAPrivateKey=#'RSAPrivateKey'{modulus=Modulus})
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso (is_binary(Salt) orelse is_integer(Salt)) ->
	ModBits = int_to_bit_size(Modulus),
	case emsa_pss_encode(Hash, Message, Salt, ModBits - 1) of
		{ok, EM} ->
			ModBytes = int_to_byte_size(Modulus),
			S = pad_to_key_size(ModBytes, dp(EM, RSAPrivateKey)),
			{ok, S};
		EncodingError ->
			EncodingError
	end;
rsassa_pss_sign(Hash, Message, Salt, RSAPrivateKey=#'RSAPrivateKey'{})
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsassa_pss_sign(HashFun, Message, Salt, RSAPrivateKey).

%% See [https://tools.ietf.org/html/rfc3447#section-8.1.2]
-spec rsassa_pss_verify(Hash, Message, Signature, RSAPublicKey) -> boolean()
	when
		Hash         :: rsa_hash_fun(),
		Message      :: binary(),
		Signature    :: binary(),
		RSAPublicKey :: rsa_public_key().
rsassa_pss_verify(Hash, Message, Signature, RSAPublicKey=#'RSAPublicKey'{modulus=Modulus})
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_binary(Signature) ->
	ModBytes = int_to_byte_size(Modulus),
	case byte_size(Signature) =:= ModBytes of
		true ->
			ModBits = int_to_bit_size(Modulus),
			EM = pad_to_key_size(ceiling((ModBits - 1) / 8), ep(Signature, RSAPublicKey)),
			emsa_pss_verify(Hash, Message, EM, ModBits - 1);
		false ->
			false
	end;
rsassa_pss_verify(Hash, Message, Signature, RSAPublicKey=#'RSAPublicKey'{})
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsassa_pss_verify(HashFun, Message, Signature, RSAPublicKey).

%% See [https://tools.ietf.org/html/rfc3447#section-8.1.2]
-spec rsassa_pss_verify(Hash, Message, Signature, SaltLen, RSAPublicKey) -> boolean()
	when
		Hash         :: rsa_hash_fun(),
		Message      :: binary(),
		Signature    :: binary(),
		SaltLen      :: integer(),
		RSAPublicKey :: rsa_public_key().
rsassa_pss_verify(Hash, Message, Signature, SaltLen, RSAPublicKey=#'RSAPublicKey'{modulus=Modulus})
		when is_function(Hash, 1)
		andalso is_binary(Message)
		andalso is_binary(Signature)
		andalso is_integer(SaltLen) ->
	ModBytes = int_to_byte_size(Modulus),
	case byte_size(Signature) =:= ModBytes of
		true ->
			ModBits = int_to_bit_size(Modulus),
			EM = pad_to_key_size(ceiling((ModBits - 1) / 8), ep(Signature, RSAPublicKey)),
			emsa_pss_verify(Hash, Message, EM, SaltLen, ModBits - 1);
		false ->
			false
	end;
rsassa_pss_verify(Hash, Message, Signature, SaltLen, RSAPublicKey=#'RSAPublicKey'{})
		when is_tuple(Hash)
		orelse is_atom(Hash) ->
	HashFun = resolve_hash(Hash),
	rsassa_pss_verify(HashFun, Message, Signature, SaltLen, RSAPublicKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
ceiling(X) when X < 0 ->
	trunc(X);
ceiling(X) ->
	T = trunc(X),
	case X - T == 0 of
		false ->
			T + 1;
		true ->
			T
	end.

%% @private
derive_mgf1(_Hash, Reps, Reps, _Seed, MaskLen, T) ->
	binary:part(T, 0, MaskLen);
derive_mgf1(Hash, Counter, Reps, Seed, MaskLen, T) ->
	CounterBin = << Counter:8/unsigned-big-integer-unit:4 >>,
	NewT = << T/binary, (Hash(<< Seed/binary, CounterBin/binary >>))/binary >>,
	derive_mgf1(Hash, Counter + 1, Reps, Seed, MaskLen, NewT).

%% @private
dp(B, #'RSAPrivateKey'{modulus=N, privateExponent=E}) ->
	crypto:mod_pow(B, E, N).

%% @private
ep(B, #'RSAPublicKey'{modulus=N, publicExponent=E}) ->
	crypto:mod_pow(B, E, N).

%% @private
int_to_bit_size(I) ->
	int_to_bit_size(I, 0).

%% @private
int_to_bit_size(0, B) ->
	B;
int_to_bit_size(I, B) ->
	int_to_bit_size(I bsr 1, B + 1).

%% @private
int_to_byte_size(I) ->
	int_to_byte_size(I, 0).

%% @private
int_to_byte_size(0, B) ->
	B;
int_to_byte_size(I, B) ->
	int_to_byte_size(I bsr 8, B + 1).

%% @private
pad_to_key_size(Bytes, Data) when byte_size(Data) < Bytes ->
	pad_to_key_size(Bytes, << 0, Data/binary >>);
pad_to_key_size(_Bytes, Data) ->
	Data.

%% @private
resolve_hash(HashFun) when is_function(HashFun, 1) ->
	HashFun;
resolve_hash(DigestType) when is_atom(DigestType) ->
	fun(Data) ->
		crypto:hash(DigestType, Data)
	end;
resolve_hash({hmac, DigestType, Key}) when is_atom(DigestType) ->
	fun(Data) ->
		crypto:hmac(DigestType, Key, Data)
	end.
