#ifndef _LIBCLI_AUTH_PROTO_H__
#define _LIBCLI_AUTH_PROTO_H__

#undef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2) PRINTF_ATTRIBUTE(a1, a2)

#include "lib/crypto/gnutls_helpers.h"

/* this file contains prototypes for functions that are private
 * to this subsystem or library. These functions should not be
 * used outside this particular subsystem! */


/* The following definitions come from libcli/auth/credentials.c  */

bool netlogon_creds_is_random_challenge(const struct netr_Credential *challenge);
void netlogon_creds_random_challenge(struct netr_Credential *challenge);

NTSTATUS netlogon_creds_des_encrypt(struct netlogon_creds_CredentialState *creds,
				    struct samr_Password *pass);
NTSTATUS netlogon_creds_des_decrypt(struct netlogon_creds_CredentialState *creds,
				    struct samr_Password *pass);
NTSTATUS netlogon_creds_arcfour_crypt(struct netlogon_creds_CredentialState *creds,
				      uint8_t *data,
				      size_t len);
NTSTATUS netlogon_creds_aes_encrypt(struct netlogon_creds_CredentialState *creds,
				    uint8_t *data,
				    size_t len);
NTSTATUS netlogon_creds_aes_decrypt(struct netlogon_creds_CredentialState *creds,
				    uint8_t *data,
				    size_t len);

/* These should not be used directly! */
#define netlogon_creds_des_encrypt __DO_NOT_USE_netlogon_creds_des_encrypt
#define netlogon_creds_des_decrypt __DO_NOT_USE_netlogon_creds_des_decrypt
#define netlogon_creds_arcfour_crypt __DO_NOT_USE_netlogon_creds_arcfour_crypt
#define netlogon_creds_aes_encrypt __DO_NOT_USE_netlogon_creds_aes_encrypt
#define netlogon_creds_aes_decrypt __DO_NOT_USE_netlogon_creds_aes_decrypt

struct netlogon_creds_CredentialState *netlogon_creds_kerberos_init(TALLOC_CTX *mem_ctx,
								    const char *client_account,
								    const char *client_computer_name,
								    uint16_t secure_channel_type,
								    uint32_t client_requested_flags,
								    const struct dom_sid *client_sid,
								    uint32_t negotiate_flags);

/*****************************************************************
The above functions are common to the client and server interface
next comes the client specific functions
******************************************************************/
struct netlogon_creds_CredentialState *netlogon_creds_client_init(TALLOC_CTX *mem_ctx,
								  const char *client_account,
								  const char *client_computer_name,
								  uint16_t secure_channel_type,
								  const struct netr_Credential *client_challenge,
								  const struct netr_Credential *server_challenge,
								  const struct samr_Password *machine_password,
								  struct netr_Credential *initial_credential,
								  uint32_t client_requested_flags,
								  uint32_t negotiate_flags);
NTSTATUS
netlogon_creds_client_authenticator(struct netlogon_creds_CredentialState *creds,
				    struct netr_Authenticator *next);
NTSTATUS netlogon_creds_client_verify(struct netlogon_creds_CredentialState *creds,
			const struct netr_Credential *received_credentials,
			enum dcerpc_AuthType auth_type,
			enum dcerpc_AuthLevel auth_level);
bool netlogon_creds_client_check(struct netlogon_creds_CredentialState *creds,
			const struct netr_Credential *received_credentials);
struct netlogon_creds_CredentialState *netlogon_creds_copy(
	TALLOC_CTX *mem_ctx,
	const struct netlogon_creds_CredentialState *creds_in);

/*****************************************************************
The above functions are common to the client and server interface
next comes the server specific functions
******************************************************************/
struct netlogon_creds_CredentialState *netlogon_creds_server_init(TALLOC_CTX *mem_ctx,
								  const char *client_account,
								  const char *client_computer_name,
								  uint16_t secure_channel_type,
								  const struct netr_Credential *client_challenge,
								  const struct netr_Credential *server_challenge,
								  const struct samr_Password *machine_password,
								  const struct netr_Credential *credentials_in,
								  struct netr_Credential *credentials_out,
								  uint32_t client_requested_flags,
								  const struct dom_sid *client_sid,
								  uint32_t negotiate_flags);
NTSTATUS netlogon_creds_server_step_check(struct netlogon_creds_CredentialState *creds,
				 const struct netr_Authenticator *received_authenticator,
				 struct netr_Authenticator *return_authenticator,
				 enum dcerpc_AuthType auth_type,
				 enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_decrypt_samlogon_validation(struct netlogon_creds_CredentialState *creds,
						    uint16_t validation_level,
						    union netr_Validation *validation,
						    enum dcerpc_AuthType auth_type,
						    enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_encrypt_samlogon_validation(struct netlogon_creds_CredentialState *creds,
						    uint16_t validation_level,
						    union netr_Validation *validation,
						    enum dcerpc_AuthType auth_type,
						    enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_decrypt_samlogon_logon(struct netlogon_creds_CredentialState *creds,
					       enum netr_LogonInfoClass level,
					       union netr_LogonLevel *logon,
					       enum dcerpc_AuthType auth_type,
					       enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_encrypt_samlogon_logon(struct netlogon_creds_CredentialState *creds,
					       enum netr_LogonInfoClass level,
					       union netr_LogonLevel *logon,
					       enum dcerpc_AuthType auth_type,
					       enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_decrypt_samr_Password(struct netlogon_creds_CredentialState *creds,
					      struct samr_Password *pass,
					      enum dcerpc_AuthType auth_type,
					      enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_encrypt_samr_Password(struct netlogon_creds_CredentialState *creds,
					      struct samr_Password *pass,
					      enum dcerpc_AuthType auth_type,
					      enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_decrypt_samr_CryptPassword(struct netlogon_creds_CredentialState *creds,
						   struct samr_CryptPassword *pass,
						   enum dcerpc_AuthType auth_type,
						   enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_encrypt_samr_CryptPassword(struct netlogon_creds_CredentialState *creds,
						   struct samr_CryptPassword *pass,
						   enum dcerpc_AuthType auth_type,
						   enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_decrypt_SendToSam(struct netlogon_creds_CredentialState *creds,
					  uint8_t *opaque_data,
					  size_t opaque_length,
					  enum dcerpc_AuthType auth_type,
					  enum dcerpc_AuthLevel auth_level);
NTSTATUS netlogon_creds_encrypt_SendToSam(struct netlogon_creds_CredentialState *creds,
					  uint8_t *opaque_data,
					  size_t opaque_length,
					  enum dcerpc_AuthType auth_type,
					  enum dcerpc_AuthLevel auth_level);
union netr_LogonLevel *netlogon_creds_shallow_copy_logon(TALLOC_CTX *mem_ctx,
					enum netr_LogonInfoClass level,
					const union netr_LogonLevel *in);

/* The following definitions come from libcli/auth/session.c  */

int sess_crypt_blob(DATA_BLOB *out, const DATA_BLOB *in, const DATA_BLOB *session_key,
		    enum samba_gnutls_direction encrypt);
DATA_BLOB sess_encrypt_string(const char *str, const DATA_BLOB *session_key);
char *sess_decrypt_string(TALLOC_CTX *mem_ctx,
			  DATA_BLOB *blob, const DATA_BLOB *session_key);
DATA_BLOB sess_encrypt_blob(TALLOC_CTX *mem_ctx, DATA_BLOB *blob_in, const DATA_BLOB *session_key);
NTSTATUS sess_decrypt_blob(TALLOC_CTX *mem_ctx, const DATA_BLOB *blob, const DATA_BLOB *session_key,
			   DATA_BLOB *ret);

/* The following definitions come from libcli/auth/smbencrypt.c  */

int SMBencrypt_hash(const uint8_t lm_hash[16], const uint8_t *c8, uint8_t p24[24]);
bool SMBencrypt(const char *passwd, const uint8_t *c8, uint8_t p24[24]);

/**
 * Creates the MD4 Hash of the users password in NT UNICODE.
 * @param passwd password in 'unix' charset.
 * @param p16 return password hashed with md4, caller allocated 16 byte buffer
 */
bool E_md4hash(const char *passwd, uint8_t p16[16]);

/**
 * Creates the DES forward-only Hash of the users password in DOS ASCII charset
 * @param passwd password in 'unix' charset.
 * @param p16 return password hashed with DES, caller allocated 16 byte buffer
 * @return false if password was > 14 characters, and therefore may be incorrect, otherwise true
 * @note p16 is filled in regardless
 */
bool E_deshash(const char *passwd, uint8_t p16[16]);

/**
 * Creates the MD4 and DES (LM) Hash of the users password.
 * MD4 is of the NT Unicode, DES is of the DOS UPPERCASE password.
 * @param passwd password in 'unix' charset.
 * @param nt_p16 return password hashed with md4, caller allocated 16 byte buffer
 * @param p16 return password hashed with des, caller allocated 16 byte buffer
 */
void nt_lm_owf_gen(const char *pwd, uint8_t nt_p16[16], uint8_t p16[16]);
bool ntv2_owf_gen(const uint8_t owf[16],
		  const char *user_in, const char *domain_in,
		  uint8_t kr_buf[16]);
int SMBOWFencrypt(const uint8_t passwd[16], const uint8_t *c8, uint8_t p24[24]);
int SMBNTencrypt_hash(const uint8_t nt_hash[16], const uint8_t *c8, uint8_t *p24);
int SMBNTencrypt(const char *passwd, const uint8_t *c8, uint8_t *p24);
NTSTATUS SMBOWFencrypt_ntv2(const uint8_t kr[16],
			    const DATA_BLOB *srv_chal,
			    const DATA_BLOB *smbcli_chal,
			    uint8_t resp_buf[16]);
NTSTATUS SMBsesskeygen_ntv2(const uint8_t kr[16],
			    const uint8_t *nt_resp,
			    uint8_t sess_key[16]);
void SMBsesskeygen_ntv1(const uint8_t kr[16], uint8_t sess_key[16]);
NTSTATUS SMBsesskeygen_lm_sess_key(const uint8_t lm_hash[16],
				   const uint8_t lm_resp[24], /* only uses 8 */
				   uint8_t sess_key[16]);
DATA_BLOB NTLMv2_generate_names_blob(TALLOC_CTX *mem_ctx,
				     const char *hostname,
				     const char *domain);
bool SMBNTLMv2encrypt_hash(TALLOC_CTX *mem_ctx,
			   const char *user, const char *domain, const uint8_t nt_hash[16],
			   const DATA_BLOB *server_chal,
			   const NTTIME *server_timestamp,
			   const DATA_BLOB *names_blob,
			   DATA_BLOB *lm_response, DATA_BLOB *nt_response,
			   DATA_BLOB *lm_session_key, DATA_BLOB *user_session_key) ;
bool SMBNTLMv2encrypt(TALLOC_CTX *mem_ctx,
		      const char *user, const char *domain,
		      const char *password,
		      const DATA_BLOB *server_chal,
		      const DATA_BLOB *names_blob,
		      DATA_BLOB *lm_response, DATA_BLOB *nt_response,
		      DATA_BLOB *lm_session_key, DATA_BLOB *user_session_key) ;
struct lsa_TrustDomainInfoInfoEx;
struct lsa_ForestTrustInformation2;
struct trust_forest_domain_info {
	bool is_local_forest;
	bool is_checked_trust;
	struct lsa_TrustDomainInfoInfoEx *tdo;
	struct lsa_ForestTrustInformation2 *fti;
};
NTSTATUS NTLMv2_RESPONSE_verify_netlogon_creds(const char *account_name,
			const char *account_domain,
			const DATA_BLOB response,
			const struct netlogon_creds_CredentialState *creds,
			const char *workgroup,
			size_t num_domains,
			const struct trust_forest_domain_info *domains,
			TALLOC_CTX *mem_ctx,
			char **_computer_name);

/***********************************************************
 encode a password buffer with a unicode password.  The buffer
 is filled with random data to make it harder to attack.
************************************************************/
bool encode_pw_buffer(uint8_t buffer[516], const char *password, int string_flags);

/***********************************************************
 decode a password buffer
 *new_pw_len is the length in bytes of the possibly mulitbyte
 returned password including termination.
************************************************************/
bool decode_pw_buffer(TALLOC_CTX *ctx,
		      uint8_t in_buffer[516],
		      char **pp_new_pwrd,
		      size_t *new_pw_len,
		      charset_t string_charset);

/**
 * @brief Encode an password buffer before we encrypt it.
 *
 * @param buffer[514]   The buffer to encode into.
 *
 * @param password      The password we want to encode into the buffer.
 *
 * @param string_flags  String flags for encoding (e.g. STR_UNICODE).
 *
 * @return true on success, false otherwise.
 */
bool encode_pwd_buffer514_from_str(uint8_t buffer[514],
				   const char *password,
				   uint32_t string_flags);

/**
 * @brief Extract AES password blob from buffer.
 *
 * This extracts the password from the in_buffer as a data blob. It should
 * then contain an UTF-16 encoded password.
 *
 * @param mem_ctx       The memory context to allowcate the password on.
 *
 * @param in_buffer[514] The input buffer to extract the password from.
 *
 * @param new_password  A pointer to the store the extracted password blob.
 *
 * @return true on success, false otherwise.
 */
bool extract_pwd_blob_from_buffer514(TALLOC_CTX *mem_ctx,
				     const uint8_t in_buffer[514],
				     DATA_BLOB *new_password);

/**
 * @brief Decode AES password buffer to password in the given charset.
 *
 * @param mem_ctx       The memory context to allocate the decoded password on.
 *
 * @param in_buffer[514] The in buffer with the decrypted password data.
 *
 * @param string_charset The charset to decode to.
 *
 * @param decoded_password A pointer to store the blob for the decoded password.
 *                         It ensures that the password is NULL terminated.
 *
 * @return true on success, false otherwise.
 */
bool decode_pwd_string_from_buffer514(TALLOC_CTX *mem_ctx,
				      const uint8_t in_buffer[514],
				      charset_t string_charset,
				      DATA_BLOB *decoded_password);

/***********************************************************
 Encode an arc4 password change buffer.
************************************************************/
NTSTATUS encode_rc4_passwd_buffer(const char *passwd,
				  const DATA_BLOB *session_key,
				  struct samr_CryptPasswordEx *out_crypt_pwd);

/***********************************************************
 Decode an arc4 encrypted password change buffer.
************************************************************/
NTSTATUS decode_rc4_passwd_buffer(const DATA_BLOB *psession_key,
				  struct samr_CryptPasswordEx *inout_crypt_pwd);

/***********************************************************
 encode a password buffer with an already unicode password.  The
 rest of the buffer is filled with random data to make it harder to attack.
************************************************************/
bool set_pw_in_buffer(uint8_t buffer[516], const DATA_BLOB *password);

/***********************************************************
 decode a password buffer
 *new_pw_size is the length in bytes of the extracted unicode password
************************************************************/
bool extract_pw_from_buffer(TALLOC_CTX *mem_ctx,
			    uint8_t in_buffer[516], DATA_BLOB *new_pass);
struct wkssvc_PasswordBuffer;
WERROR encode_wkssvc_join_password_buffer(TALLOC_CTX *mem_ctx,
					  const char *pwd,
					  DATA_BLOB *session_key,
					  struct wkssvc_PasswordBuffer **pwd_buf);
WERROR decode_wkssvc_join_password_buffer(TALLOC_CTX *mem_ctx,
					  struct wkssvc_PasswordBuffer *pwd_buf,
					  DATA_BLOB *session_key,
					  char **pwd);

/* The following definitions come from libcli/auth/smbdes.c  */

int des_crypt56_gnutls(uint8_t out[8], const uint8_t in[8], const uint8_t key[7],
		       enum samba_gnutls_direction encrypt);
int E_P16(const uint8_t *p14,uint8_t *p16);
int E_P24(const uint8_t *p21, const uint8_t *c8, uint8_t *p24);
int E_old_pw_hash( uint8_t *p14, const uint8_t *in, uint8_t *out);
int des_crypt128(uint8_t out[8], const uint8_t in[8], const uint8_t key[16]);
int des_crypt112(uint8_t out[8], const uint8_t in[8], const uint8_t key[14],
		 enum samba_gnutls_direction encrypt);
int des_crypt112_16(uint8_t out[16], const uint8_t in[16], const uint8_t key[14],
		    enum samba_gnutls_direction encrypt);
int sam_rid_crypt(unsigned int rid, const uint8_t *in, uint8_t *out,
		  enum samba_gnutls_direction encrypt);
#undef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2)

#endif

