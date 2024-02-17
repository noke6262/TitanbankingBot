#include "diffie_hellman.h"
#ifdef DEBUG_CODE
#include <stdio.h>
#endif
BOOL Generate_Values(PUCHAR *generator, PUCHAR *prime)
{
	BCRYPT_ALG_HANDLE dh_algo_provider = NULL;
	BCRYPT_KEY_HANDLE dh_private_key = NULL;
	BOOL status = FALSE;
	PBYTE dh_private_key_blob = NULL;
	ULONG dh_private_key_blob_size = 0;

	NTSTATUS api_status = BCryptOpenAlgorithmProvider(&dh_algo_provider, BCRYPT_DH_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptOpenAlgorithmProvider", api_status);
#endif
		goto cleanup;
	}

	api_status = BCryptGenerateKeyPair(dh_algo_provider, &dh_private_key, DHKEYSIZE, 0);
	if (!NT_SUCCESS(api_status))
	{

#ifdef DEBUG_CODE
		report_error("BCryptGenerateKeyPair", api_status);
#endif
		goto cleanup;
	}

	api_status = BCryptFinalizeKeyPair(dh_private_key, 0);
	if (!NT_SUCCESS(api_status))
	{

#ifdef DEBUG_CODE
		report_error("BCryptFinalizeKeyPair", api_status);
#endif
		goto cleanup;
	}

	api_status = BCryptExportKey(dh_private_key, NULL, BCRYPT_DH_PRIVATE_BLOB, NULL, 0, &dh_private_key_blob_size, 0);
	if (!NT_SUCCESS(api_status))
	{

#ifdef DEBUG_CODE
		report_error("BCryptExportKey size", api_status);
#endif
		goto cleanup;
	}

	dh_private_key_blob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dh_private_key_blob_size);
	if (NULL == dh_private_key_blob)
	{
#ifdef DEBUG_CODE
		api_status = STATUS_NO_MEMORY;
		report_error("HeapAlloc private key blob", api_status);
#endif
		goto cleanup;
	}


	api_status = BCryptExportKey(dh_private_key, NULL, BCRYPT_DH_PRIVATE_BLOB, dh_private_key_blob, dh_private_key_blob_size, &dh_private_key_blob_size, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptExportKey data", api_status);
#endif
		goto cleanup;
	}
	*prime = HeapAlloc(GetProcessHeap(), 0, (DHKEYSIZE / 8));
	memcpy(*prime, dh_private_key_blob + sizeof(BCRYPT_DH_KEY_BLOB), (DHKEYSIZE / 8));
	*generator = HeapAlloc(GetProcessHeap(), 0, (DHKEYSIZE / 8));
	memcpy(*generator, dh_private_key_blob + sizeof(BCRYPT_DH_KEY_BLOB) + (DHKEYSIZE / 8), (DHKEYSIZE / 8));
#ifdef DEBUG_CODE
	print_hex_c_dump("dh_prime", *prime, (DHKEYSIZE / 8), 8);
	print_hex_c_dump("dh_generator", *generator, (DHKEYSIZE / 8), 8);

	//print_hex_php_dump("dh_prime", *prime, (DHKEYSIZE / 8));
	//print_hex_php_dump("dh_generator", *generator, (DHKEYSIZE / 8));
#endif
	status = TRUE;
cleanup:

	if (dh_private_key_blob)
		HeapFree(GetProcessHeap(), 0, dh_private_key_blob);

	if (dh_private_key)
		BCryptDestroyKey(dh_private_key);

	if (dh_algo_provider)
		BCryptCloseAlgorithmProvider(dh_algo_provider, 0);

	return status;
}


BOOL GenerateSalt(PCHAR *Salt, ULONG ulSalt) {
	BOOL status = FALSE;
	*Salt = HeapAlloc(GetProcessHeap(), 0, ulSalt);
	if (*Salt) {
		NTSTATUS api_status = BCryptGenRandom(NULL, (PBYTE)*Salt, ulSalt, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (NT_SUCCESS(api_status))
		{
			status = TRUE;
		}
	}
	return status;
}
BOOL InitCryptoKey(PCRYPTO_KEY pCryptoKey, LPWSTR lpszHwid, DWORD dwHwid, PCHAR lpszPage, PCHAR lpszHost) {
	PUCHAR Generator = NULL;
	PUCHAR Prime = NULL;
	PCHAR lpszSecretHashPassword = NULL;
	PCHAR Salt = NULL;
	DWORD ulSalt = 10;
	DWORD dwSecretHashSize;
	BOOL status = Generate_Values(&Generator, &Prime);
	if (!status) {
		goto cleanup;
	}
	status = GenerateSalt(&Salt, ulSalt);
	if (!status) {
		goto cleanup;
	}
	status = Exchange_Keys(&Generator, &Prime, pCryptoKey, &lpszSecretHashPassword, &dwSecretHashSize, lpszHwid, dwHwid, lpszPage, lpszHost, Salt, ulSalt);
	if (!status) {
		goto cleanup;
	}
	status = PrepareAES(&lpszSecretHashPassword, dwSecretHashSize, pCryptoKey, lpszHwid, dwHwid, lpszPage, lpszHost, &Salt, ulSalt);
	if (!status) {
		goto cleanup;
	}

cleanup:

	if (lpszSecretHashPassword)
		HeapFree(GetProcessHeap(), 0, lpszSecretHashPassword);

	if (Salt)
		HeapFree(GetProcessHeap(), 0, Salt);

	if (Generator)
		HeapFree(GetProcessHeap(), 0, Generator);

	if (Prime)
		HeapFree(GetProcessHeap(), 0, Prime);


	return TRUE;
}

BOOL Exchange_Keys(PUCHAR *dh_generator, PUCHAR *dh_prime, PCRYPTO_KEY pCryptoKey, PCHAR *secret_hash_hex, PDWORD pdwSecret_Hash_Hex, LPWSTR lpszHwid, DWORD dwHwid, PCHAR lpszPage, PCHAR lpszHost, PCHAR salt, DWORD dwSalt)
{
	BOOL status = FALSE;
	BCRYPT_ALG_HANDLE dh_algo_provider = NULL;
	BCRYPT_KEY_HANDLE dh_private_key = NULL, dh_public_key = NULL;
	ULONG DhSpecialSize = DHKEYSIZE / 8, dh_pubkey_blob_size = 0, secret_hash_size = 0, dh_param_blob_size = 0;
	PBYTE dh_param_blob = NULL, dh_pubkey_blob = NULL, secret_hash = NULL, dh_pubkey_hex = NULL,
		dh_hex_prime = NULL, dh_hex_gen = NULL, Salt_hex = NULL, remote_pubkey = NULL, remote_pubkey_hex = NULL;
	BCRYPT_SECRET_HANDLE secret = NULL;

	NTSTATUS api_status = BCryptOpenAlgorithmProvider(&dh_algo_provider, BCRYPT_DH_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptOpenAlgorithmProvider", api_status);
#endif
		goto cleanup;
	}

	api_status = BCryptGenerateKeyPair(dh_algo_provider, &dh_private_key, DHKEYSIZE, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptGenerateKeyPair", api_status);
#endif
		goto cleanup;
	}

	dh_param_blob_size = sizeof(BCRYPT_DH_PARAMETER_HEADER) + DhSpecialSize + DhSpecialSize;
	dh_param_blob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dh_param_blob_size);
	if (!dh_param_blob)
	{
#ifdef DEBUG_CODE
		api_status = STATUS_NO_MEMORY;
		report_error("HeapAlloc dh_param_blob", api_status);
#endif
		goto cleanup;
	}
	ZeroBuffer(dh_param_blob, dh_param_blob_size);
	BCRYPT_DH_PARAMETER_HEADER* dh_parameter_header = (BCRYPT_DH_PARAMETER_HEADER *)dh_param_blob;

	dh_parameter_header->cbLength = dh_param_blob_size;
	dh_parameter_header->cbKeyLength = DHKEYSIZE / 8;
	dh_parameter_header->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

	memcpy(dh_param_blob + sizeof(BCRYPT_DH_PARAMETER_HEADER), *dh_prime, DhSpecialSize);
	memcpy(dh_param_blob + sizeof(BCRYPT_DH_PARAMETER_HEADER) + DhSpecialSize, *dh_generator, DhSpecialSize);

	api_status = BCryptSetProperty(dh_private_key, BCRYPT_DH_PARAMETERS, dh_param_blob, dh_param_blob_size, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptSetProperty BCRYPT_DH_PARAMETERS", api_status);
#endif
		goto cleanup;
	}
	api_status = BCryptFinalizeKeyPair(dh_private_key, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptFinalizeKeyPair", api_status);
#endif
		goto cleanup;
	}

	//export public key
	api_status = BCryptExportKey(dh_private_key, NULL, BCRYPT_DH_PUBLIC_BLOB, NULL, 0, &dh_pubkey_blob_size, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptExportKey pubkey size", api_status);
#endif
		goto cleanup;
	}

	dh_pubkey_blob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dh_pubkey_blob_size);
	if (NULL == dh_pubkey_blob)
	{
#ifdef DEBUG_CODE
		api_status = STATUS_NO_MEMORY;
		report_error("HeapAlloc dh pubkey blob", api_status);
#endif
		goto cleanup;
	}
	api_status = BCryptExportKey(dh_private_key, NULL, BCRYPT_DH_PUBLIC_BLOB, dh_pubkey_blob, dh_pubkey_blob_size, &dh_pubkey_blob_size, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptExportKey pubkey data", api_status);
#endif
		goto cleanup;
	}

	//pubkey blob = [key blob header][modulus][generator][public key]
	dh_pubkey_hex = bytes_to_hex(dh_pubkey_blob + sizeof(BCRYPT_DH_KEY_BLOB) + (DHKEYSIZE / 8) + (DHKEYSIZE / 8), (DHKEYSIZE / 8));
	if (!dh_pubkey_hex)
	{
#ifdef DEBUG_CODE
		api_status = STATUS_NO_MEMORY;
		report_error("malloc dh pubkey hex", api_status);
#endif
		goto cleanup;
	}

	dh_hex_prime = bytes_to_hex(*dh_prime, 64);
	dh_hex_gen = bytes_to_hex(*dh_generator, 64);
	Salt_hex = bytes_to_hex(salt, dwSalt);
	// do this
	DWORD dwContentLength = 128 + 128 + 128 + dwSalt * 2 + dwHwid + 38;
	DWORD dwContent = 128 + 128 + 128 + dwSalt*2 + (dwHwid*sizeof(WCHAR)) + 38; // first length is 64*2 which is pubkey_hex
	// second length is the prime, third is the gen value
	// fourth is the salt length and fifth is the HWID length and sixth is the normal content length.

	PCHAR lpszContent = HeapAlloc(GetProcessHeap(), 0, dwContent + 1);
	ZeroBuffer(lpszContent, dwContent + 1);
	wsprintfA(lpszContent, "&hwid=%S&pubkey=%s&dh_prime=%s&dh_gen=%s&salt=%s", lpszHwid, dh_pubkey_hex, dh_hex_prime, dh_hex_gen, Salt_hex);
#ifdef DEBUG_CODE
	print_hex_c_dump("dh_prime2", *dh_prime, (DHKEYSIZE / 8), 8);
	print_hex_c_dump("dh_generator2", *dh_generator, (DHKEYSIZE / 8), 8);
	printf_s("localhost/bcrypt_index.php?pubkey=%s&dh_prime=%s&dh_gen=%s&salt=%s\n", dh_pubkey_hex, dh_hex_prime, dh_hex_gen, Salt_hex);


#endif
	DWORD dwData = 0;
	if (!PostRequest(lpszPage, lpszHost, lpszContent, dwContentLength, &remote_pubkey_hex, &dwData, TRUE))
		goto cleanup;
	//get remote public key
	remote_pubkey = hex_to_bytes(remote_pubkey_hex);
	if (remote_pubkey == NULL)
	{
#ifdef DEBUG_CODE
		api_status = STATUS_NO_MEMORY;
		report_error("malloc remote pubkey bytes", api_status);
#endif
		goto cleanup;
	}

	memcpy_s(dh_pubkey_blob + sizeof(BCRYPT_DH_KEY_BLOB) + (DHKEYSIZE / 8) + (DHKEYSIZE / 8), (DHKEYSIZE / 8),
		remote_pubkey, (DHKEYSIZE / 8));

	api_status = BCryptImportKeyPair(dh_algo_provider, NULL, BCRYPT_DH_PUBLIC_BLOB, &dh_public_key, dh_pubkey_blob, dh_pubkey_blob_size, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptImportKeyPair", api_status);
#endif
		goto cleanup;
	}

	api_status = BCryptCloseAlgorithmProvider(dh_algo_provider, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptCloseAlgorithmProvider", api_status);
#endif
		goto cleanup;
	}

	dh_algo_provider = 0;

	api_status = BCryptSecretAgreement(dh_private_key, dh_public_key, &secret, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptSecretAgreement", api_status);
#endif
		goto cleanup;
	}

	BCryptBuffer hash_param = { sizeof(BCRYPT_SHA1_ALGORITHM), KDF_HASH_ALGORITHM, BCRYPT_SHA1_ALGORITHM };
	BCryptBufferDesc hash_params = { BCRYPTBUFFER_VERSION, 1, &hash_param };

	api_status = BCryptDeriveKey(secret, BCRYPT_KDF_HASH, &hash_params, NULL, 0, &secret_hash_size, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptDeriveKey size", api_status);
#endif
		goto cleanup;
	}

	secret_hash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, secret_hash_size);
	if (!secret_hash)
	{
#ifdef DEBUG_CODE
		api_status = STATUS_NO_MEMORY;
		report_error("HeapAlloc secret_hash", api_status);
#endif
		goto cleanup;
	}

	api_status = BCryptDeriveKey(secret, BCRYPT_KDF_HASH, &hash_params, secret_hash, secret_hash_size, &secret_hash_size, 0);
	if (!NT_SUCCESS(api_status))
	{
#ifdef DEBUG_CODE
		report_error("BCryptDeriveKey data", api_status);
#endif
		goto cleanup;
	}

	*secret_hash_hex = bytes_to_hex(secret_hash, secret_hash_size);

	if (!*secret_hash_hex)
	{
#ifdef DEBUG_CODE
		api_status = STATUS_NO_MEMORY;
		report_error("malloc secret_hash_hex", api_status);
#endif
		goto cleanup;
	}

	*pdwSecret_Hash_Hex = secret_hash_size * 2;

#ifdef DEBUG_CODE
	printf_s("[+] secret_hash: %s\n", *secret_hash_hex);
#endif
	status = TRUE;

cleanup:

	if (secret_hash)
		HeapFree(GetProcessHeap(), 0, secret_hash);

	if (dh_hex_prime)
		HeapFree(GetProcessHeap(), 0, dh_hex_prime);

	if (dh_hex_gen)
		HeapFree(GetProcessHeap(), 0, dh_hex_gen);


	if (remote_pubkey_hex)
		HeapFree(GetProcessHeap(), 0, remote_pubkey_hex);
	
	if (remote_pubkey)
		HeapFree(GetProcessHeap(), 0, remote_pubkey);
	
	if (Salt_hex)
		HeapFree(GetProcessHeap(), 0, Salt_hex);

	if (dh_pubkey_hex)
		HeapFree(GetProcessHeap(), 0, dh_pubkey_hex);

	if (dh_pubkey_blob)
		HeapFree(GetProcessHeap(), 0, dh_pubkey_blob);

	if (dh_param_blob)
		HeapFree(GetProcessHeap(), 0, dh_param_blob);

	if (secret)
		BCryptDestroySecret(secret);

	if (dh_public_key)
		BCryptDestroyKey(dh_public_key);

	if (dh_private_key)
		BCryptDestroyKey(dh_private_key);

	if (dh_algo_provider)
		BCryptCloseAlgorithmProvider(dh_algo_provider, 0);

	return status;
}


