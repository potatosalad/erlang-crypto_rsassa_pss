%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(crypto_rsassa_pss_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([sign_and_verify/1]).
-export([md5/1]).
-export([sha/1]).
-export([sha224/1]).
-export([sha256/1]).
-export([sha384/1]).
-export([sha512/1]).

all() ->
	[
		{group, '512'},
		{group, '1024'},
		{group, '2048'},
		{group, '4096'},
		{group, '8192'}
	].

groups() ->
	DigestTypes = [
		md5,
		sha,
		sha224,
		sha256,
		sha384,
		sha512
	],
	[
		{'512', [parallel], DigestTypes -- [sha256, sha384, sha512]},
		{'1024', [parallel], DigestTypes -- [sha512]},
		{'2048', [parallel], DigestTypes},
		{'4096', [parallel], DigestTypes},
		{'8192', [parallel], DigestTypes}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(cutkey),
	_ = application:ensure_all_started(crypto_rsassa_pss),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(crypto_rsassa_pss),
	_ = application:stop(cutkey),
	ok.

init_per_group('512', Config) ->
	[{keypair, gen_keypair(512)} | Config];
init_per_group('1024', Config) ->
	[{keypair, gen_keypair(1024)} | Config];
init_per_group('2048', Config) ->
	[{keypair, gen_keypair(2048)} | Config];
init_per_group('4096', Config) ->
	[{keypair, gen_keypair(4096)} | Config];
init_per_group('8192', Config) ->
	[{keypair, gen_keypair(8192)} | Config].

end_per_group(_Group, _Config) ->
	ok.

%%====================================================================
%% Tests
%%====================================================================

sign_and_verify(Config) ->
	DigestType = ?config(digest_type, Config),
	{PrivateKey, PublicKey} = ?config(keypair, Config),
	Message = crypto:rand_bytes(crypto:rand_uniform(256, 1024)),
	Signature = crypto_rsassa_pss:sign(Message, DigestType, PrivateKey),
	NextSignature = crypto_rsassa_pss:sign(Message, DigestType, PrivateKey),
	false = (Signature =:= NextSignature),
	true = crypto_rsassa_pss:verify(Message, DigestType, Signature, PublicKey),
	true = crypto_rsassa_pss:verify(Message, DigestType, NextSignature, PublicKey),
	ok.

md5(Config) ->
	sign_and_verify([{digest_type, md5} | Config]).

sha(Config) ->
	sign_and_verify([{digest_type, sha} | Config]).

sha224(Config) ->
	sign_and_verify([{digest_type, sha224} | Config]).

sha256(Config) ->
	sign_and_verify([{digest_type, sha256} | Config]).

sha384(Config) ->
	sign_and_verify([{digest_type, sha384} | Config]).

sha512(Config) ->
	sign_and_verify([{digest_type, sha512} | Config]).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
gen_keypair(Size) ->
	PrivateKey = gen_private_key(Size),
	{PrivateKey, make_public(PrivateKey)}.

% %% @private
% gen_public_key(Size) ->
% 	PrivateKey = gen_private_key(Size),
% 	make_public(PrivateKey).

% %% @private
% gen_private_key(Size) ->
% 	Command = lists:flatten(io_lib:format("openssl genrsa ~w 2>/dev/null", [Size])),
% 	PEM = os:cmd(Command),
% 	[PEMEntry | _] = public_key:pem_decode(iolist_to_binary(PEM)),
% 	public_key:pem_entry_decode(PEMEntry).

%% @private
gen_private_key(ModulusSize) ->
	gen_private_key(ModulusSize, 65537).

%% @private
gen_private_key(ModulusSize, ExponentSize) ->
	{ok, PrivateKey} = cutkey:rsa(ModulusSize, ExponentSize, [{return,key}]),
	PrivateKey.

%% @private
make_public(#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent}) ->
	#'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent}.
