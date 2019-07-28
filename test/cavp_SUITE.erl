%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2019, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  11 Aug 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(cavp_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("public_key/include/public_key.hrl").
-include_lib("stdlib/include/zip.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([emc_rsa_pss_sign_and_verify/1]).
-export([fips_rsa_pss_sign/1]).
-export([fips_rsa_pss_verify/1]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ok;
		T ->
			ct:fail({{M, F, A}, {expected, E}, {got, T}})
	end).

all() ->
	[
		{group, '186-3rsatestvectors'},
		{group, 'pkcs-1v2-1-vec'}
	].

groups() ->
	[
		{'186-3rsatestvectors', [parallel], [
			fips_rsa_pss_sign,
			fips_rsa_pss_verify
		]},
		{'pkcs-1v2-1-vec', [parallel], [
			emc_rsa_pss_sign_and_verify
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(crypto_rsassa_pss),
	data_setup(Config).

end_per_suite(_Config) ->
	_ = application:stop(crypto_rsassa_pss),
	ok.

init_per_group(G='186-3rsatestvectors', Config) ->
	SigGenFile = data_file("186-3rsatestvectors/SigGenPSS_186-3.txt", Config),
	SigVerFile = data_file("186-3rsatestvectors/SigVerPSS_186-3.rsp", Config),
	[{sig_gen_file, SigGenFile}, {sig_ver_file, SigVerFile} | crypto_rsassa_pss_ct:start(G, Config)];
init_per_group(G='pkcs-1v2-1-vec', Config) ->
	PSSVectFile = data_file("pkcs-1v2-1-vec/pss-vect.txt", Config),
	[{pss_vect_file, PSSVectFile} | crypto_rsassa_pss_ct:start(G, Config)].

end_per_group(_Group, Config) ->
	crypto_rsassa_pss_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

emc_rsa_pss_sign_and_verify(Config) ->
	Vectors = emc_testvector:from_file(?config(pss_vect_file, Config)),
	emc_rsa_pss_sign_and_verify(Vectors, Config).

fips_rsa_pss_sign(Config) ->
	Vectors = fips_testvector:from_file(?config(sig_gen_file, Config)),
	fips_rsa_pss_sign(Vectors, Config).

fips_rsa_pss_verify(Config) ->
	Vectors = fips_testvector:from_file(?config(sig_ver_file, Config)),
	fips_rsa_pss_verify(Vectors, Config).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
archive_file(File, Config) ->
	filename:join([?config(data_dir, Config), "archive", File]).

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
data_setup(Config) ->
	ArchiveDir = data_file("archive", Config),
	case filelib:is_dir(ArchiveDir) of
		true ->
			ok;
		false ->
			ok = file:make_dir(ArchiveDir)
	end,
	lists:foldl(fun(F, C) ->
		io:format(user, "\e[0;36m[FETCH] ~s\e[0m", [F]),
		{ok, Progress} = crypto_rsassa_pss_ct:progress_start(),
		NewC = data_setup(F, C),
		ok = crypto_rsassa_pss_ct:progress_stop(Progress),
		NewC
	end, Config, [
		"186-3rsatestvectors.zip",
		"pkcs-1v2-1-vec.zip"
	]).

%% @private
data_setup(F = "186-3rsatestvectors.zip", Config) ->
	Zip = archive_file(F, Config),
	Dir = data_file("186-3rsatestvectors", Config),
	URL = "https://github.com/potatosalad/test-vector-archive/raw/1.0.0/archive/186-3rsatestvectors.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "SigGenPSS_186-3.txt"}) ->
			true;
		(#zip_file{name = "SigVerPSS_186-3.rsp"}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "SigGenPSS_186-3.txt", Filter),
	Config;
data_setup(F = "pkcs-1v2-1-vec.zip", Config) ->
	Zip = archive_file(F, Config),
	Dir = data_file("pkcs-1v2-1-vec", Config),
	URL = "https://github.com/potatosalad/test-vector-archive/raw/1.0.0/archive/pkcs-1v2-1-vec.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "pss-vect.txt"}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "pss-vect.txt", Filter),
	Config.

%% @private
data_setup(Zip, Directory, URL) ->
	case filelib:is_file(Zip) of
		true ->
			ok;
		false ->
			ok = fetch:fetch(URL, Zip)
	end,
	case filelib:is_dir(Directory) of
		true ->
			ok;
		false ->
			ok = file:make_dir(Directory)
	end,
	ok.

%% @private
data_setup(Zip, Dir, Check, Filter) ->
	case filelib:is_file(filename:join([Dir, Check])) of
		true ->
			ok;
		false ->
			Options = case is_function(Filter, 1) of
				false ->
					[{cwd, Dir}];
				true ->
					[{cwd, Dir}, {file_filter, Filter}]
			end,
			{ok, FileList} = zip:unzip(Zip, Options),
			_ = [begin
				file:change_mode(File, 8#00644)
			end || File <- FileList],
			ok
	end.

%% @private
emc_rsa_pss_sign_and_verify([
			divider,
			{example, Example},
			{component, <<"Components of the RSA Key Pair">>},
			{vector, {<<"RSA modulus n">>, N}},
			{vector, {<<"RSA public exponent e">>, E}},
			{vector, {<<"RSA private exponent d">>, D}},
			{vector, {<<"Prime p">>, P}},
			{vector, {<<"Prime q">>, Q}},
			{vector, {<<"p's CRT exponent dP">>, DP}},
			{vector, {<<"q's CRT exponent dQ">>, DQ}},
			{vector, {<<"CRT coefficient qInv">>, QI}}
			| Vectors
		], Config) ->
	RSAPrivateKey = #'RSAPrivateKey'{
		version = 'two-prime',
		otherPrimeInfos = 'asn1_NOVALUE',
		privateExponent = crypto:bytes_to_integer(D),
		exponent1 = crypto:bytes_to_integer(DP),
		exponent2 = crypto:bytes_to_integer(DQ),
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q),
		coefficient = crypto:bytes_to_integer(QI)
	},
	RSAPublicKey = #'RSAPublicKey'{
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N)
	},
	io:format("~s", [Example]),
	emc_rsa_pss_sign_and_verify(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
emc_rsa_pss_sign_and_verify([divider], _Config) ->
	ok;
emc_rsa_pss_sign_and_verify([], _Config) ->
	ok.

%% @private
emc_rsa_pss_sign_and_verify([
			{component, Component},
			{vector, {<<"Message to be signed">>, Message}},
			{vector, {<<"Salt">>, Salt}},
			{vector, {<<"Signature">>, Signature}}
			| Vectors
		], {RSAPrivateKey, RSAPublicKey}, Config) ->
	io:format("\t~s", [Component]),
	HashFun = sha,
	case crypto_rsassa_pss:rsassa_pss_sign(HashFun, Message, Salt, RSAPrivateKey) of
		{ok, Signature} ->
			ok;
		Other ->
			ct:fail({{crypto_rsassa_pss, rsassa_pss_sign, [HashFun, Message, Salt, RSAPrivateKey]}, {expected, {ok, Signature}}, {got, Other}})
	end,
	SaltLen = byte_size(Salt),
	case crypto_rsassa_pss:rsassa_pss_verify(HashFun, Message, Signature, SaltLen, RSAPublicKey) of
		true ->
			emc_rsa_pss_sign_and_verify(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
		false ->
			ct:fail({{crypto_rsassa_pss, rsassa_pss_verify, [HashFun, Message, Signature, SaltLen, RSAPublicKey]}, {expected, true}, {got, false}})
	end;
emc_rsa_pss_sign_and_verify(Vectors = [divider | _], _RSAKeyPair, Config) ->
	emc_rsa_pss_sign_and_verify(Vectors, Config).

%% @private
fips_rsa_pss_sign([
			{option, {<<"mod">>, ModVal}},
			{vector, {<<"n">>, N}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _}
			| Vectors
		], Config) ->
	ModulusSize = binary_to_integer(ModVal),
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	fips_rsa_pss_sign(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_sign([], _Config) ->
	ok.

%% @private
fips_rsa_pss_sign([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey, Config) ->
	HashFun = shaalg_to_hash_fun(SHAAlg),
	case crypto_rsassa_pss:rsassa_pss_sign(HashFun, Msg, SaltVal, RSAPrivateKey) of
		{ok, S} ->
			ok;
		Other ->
			ct:fail({{crypto_rsassa_pss, rsassa_pss_sign, [HashFun, Msg, SaltVal, RSAPrivateKey]}, {expected, {ok, S}}, {got, Other}})
	end,
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = byte_size(SaltVal),
	case crypto_rsassa_pss:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		true ->
			fips_rsa_pss_sign(Vectors, ModulusSize, RSAPrivateKey, Config);
		false ->
			ct:fail({{crypto_rsassa_pss, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, true}, {got, false}})
	end;
fips_rsa_pss_sign(Vectors, _ModulusSize, _RSAPrivateKey, Config) ->
	fips_rsa_pss_sign(Vectors, Config).

%% @private
fips_rsa_pss_verify([
			{option, {<<"mod">>, ModVal}},
			{vector, {<<"n">>, N}, _},
			{vector, {<<"p">>, P}, _},
			{vector, {<<"q">>, Q}, _}
			| Vectors
		], Config) ->
	ModulusSize = binary_to_integer(ModVal),
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q)
	},
	fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_verify([], _Config) ->
	ok.

%% @private
fips_rsa_pss_verify([
			{vector, {<<"n">>, N}, _},
			{vector, {<<"p">>, P}, _},
			{vector, {<<"q">>, Q}, _}
			| Vectors
		], ModulusSize, Config) ->
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q)
	},
	fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_verify(Vectors, _ModulusSize, Config) ->
	fips_rsa_pss_verify(Vectors, Config).

%% @private
fips_rsa_pss_verify([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _},
			{vector, {<<"EM", _/binary>>, _}, _},
			{vector, {<<"Result">>, << R, _/binary >>}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey0, Config) ->
	Expected = case R of
		$F ->
			false;
		$P ->
			true
	end,
	HashFun = shaalg_to_hash_fun(SHAAlg),
	RSAPrivateKey = RSAPrivateKey0#'RSAPrivateKey'{
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = case SaltVal of
		<< 0 >> ->
			0;
		_ ->
			byte_size(SaltVal)
	end,
	case crypto_rsassa_pss:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		Expected ->
			fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey0, Config);
		Other ->
			ct:fail({{crypto_rsassa_pss, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, Expected}, {got, Other}})
	end;
fips_rsa_pss_verify([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _},
			{vector, {<<"Result">>, << R, _/binary >>}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey0, Config) ->
	Expected = case R of
		$F ->
			false;
		$P ->
			true
	end,
	HashFun = shaalg_to_hash_fun(SHAAlg),
	RSAPrivateKey = RSAPrivateKey0#'RSAPrivateKey'{
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = case SaltVal of
		<< 0 >> ->
			0;
		_ ->
			byte_size(SaltVal)
	end,
	case crypto_rsassa_pss:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		Expected ->
			fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey0, Config);
		Other ->
			ct:fail({{crypto_rsassa_pss, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, Expected}, {got, Other}})
	end;
fips_rsa_pss_verify(Vectors, ModulusSize, _RSAPrivateKey, Config) ->
	fips_rsa_pss_verify(Vectors, ModulusSize, Config).

%% @private
rsa_private_to_public(#'RSAPrivateKey'{ modulus = Modulus, publicExponent = PublicExponent }) ->
	#'RSAPublicKey'{ modulus = Modulus, publicExponent = PublicExponent }.

%% @private
shaalg_to_hash_fun(<<"SHA1">>)   -> sha;
shaalg_to_hash_fun(<<"SHA224">>) -> sha224;
shaalg_to_hash_fun(<<"SHA256">>) -> sha256;
shaalg_to_hash_fun(<<"SHA384">>) -> sha384;
shaalg_to_hash_fun(<<"SHA512">>) -> sha512.
