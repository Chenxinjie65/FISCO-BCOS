#ifndef __SDF_SM9_H__
#define __SDF_SM9_H__

#include <base_type.h>
#include <sdf_type.h>

#ifdef __cplusplus
extern "C" {
#endif


/* generate keypair*/
int SDF_GenerateSignMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, SM9MasterPrivateKey *pPrivateKey, SM9SignMasterPublicKey *pPuclicKey);
int SDF_GenerateEncMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, SM9MasterPrivateKey *pPrivateKey, SM9EncMasterPublicKey *pPuclicKey);
int EVDF_GenerateUserSignKey_SM9(void *hSessionHandle, unsigned int uiAlgID, SM9MasterPrivateKey *pPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9UserSignPrivateKey *vk);
int EVDF_GenerateUserEncKey_SM9(void *hSessionHandle, unsigned int uiAlgID, SM9MasterPrivateKey *pPrivateKey, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9UserEncPrivateKey *vk);
int SDF_GenerateUserSignKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9UserSignPrivateKey *vk);
int SDF_GenerateUserEncKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9UserEncPrivateKey *vk);


/* key management*/
int SDF_ExportSignMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, SM9SignMasterPublicKey *pSignMasterPubKey);
int SDF_ExportEncMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiMasterKeyindex, SM9EncMasterPublicKey *pEncMastPubKey);
int EVDF_CreateSignMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, SM9SignMasterPublicKey *pPuclicKey);
int EVDF_CreateEncMasterKeyPair_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, SM9EncMasterPublicKey *pPuclicKey);
int EVDF_CreateUserSignKey_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, unsigned int uiUserKeyindex, 
									unsigned char *pucUserID, unsigned int uiUserIDLen);
int EVDF_CreateUserEncKey_SM9(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiMasterKeyindex, unsigned int uiUserKeyindex, 
									unsigned char *pucUserID, unsigned int uiUserIDLen);
int EVDF_DeleteInternalKeyPair_SM9(void *hSessionHandle, unsigned int uiMastFlag, unsigned int uiSignFlag, unsigned int uiKeyIndex, char *AdminPIN);
int SDF_GenerateUserSignKeyWithMasterEPK_SM9(void *hSessionHandle, unsigned int indexGen, unsigned char *pucUserID, unsigned int uiUserIDLen, 
	unsigned char *pucEncID, unsigned int uiEncIDLen, SM9EncMasterPublicKey *pk, SM9PairSignEnvelopedKey *vk);
int SDF_GenerateUserEncKeyWithMasterEPK_SM9(void *hSessionHandle, unsigned int indexGen, unsigned char *pucUserID, unsigned int uiUserIDLen, 
	unsigned char *pucEncID, unsigned int uiEncIDLen, SM9EncMasterPublicKey *pk, SM9PairEncEnvelopedKey *vk);
int SDF_ImportUserSignKeyWithMasterISK_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9PairSignEnvelopedKey *pEnvelpoedKey, unsigned int *puiUserKeyIndex);
int SDF_ImportUserEncKeyWithMasterISK_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9PairEncEnvelopedKey *pEnvelpoedKey, unsigned int *puiUserKeyIndex);



/* key encap */
int EVDF_GenerateKeyWithMasterEPK_SM9(void *hSessionHandle, unsigned int uiKeyLen, SM9EncMasterPublicKey *pPublicKey, unsigned char *pucUserID, 
	unsigned int uiUserIDLen, SM9KeyPackage *pucKey, void **phKeyHandle);
int EVDF_ImportKeyWithEncKey_SM9(void *hSessionHandle, unsigned int uiKeyLen, SM9UserEncPrivateKey *vk, unsigned char *pucUserID, 
	unsigned int uiUserIDLen,  SM9KeyPackage *pucKey, void **phKeyHandle);
int SDF_GenerateKeyWithMasterEPK_SM9(void *hSessionHandle, unsigned int ulKeyLen, SM9EncMasterPublicKey *pPublicKey, unsigned char *pUserID, 
	unsigned int UserIDLen, SM9KeyPackage *pucKey, void **phKeyHandle);
int SDF_GenerateKeyWithMasterIPK_SM9(void *hSessionHandle, unsigned int ulKeyLen, unsigned int uiMasterKeyIndex, unsigned char *pUserID, 
	unsigned int UserIDLen, SM9KeyPackage *pucKey, void **phKeyHandle);
int SDF_ImportKeyWithISK_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned int uiKeyLen, SM9KeyPackage *pucKey, void **phKeyHandle);


/* key exchange */
int EVDF_GenerateAgreementDataWithSM9(void *hSessionHandle, SM9EncMasterPublicKey *pSponsorEncMastPubKey, SM9UserEncPrivateKey *pSponsorPrivateKey, unsigned int uiKeyBits, 
	unsigned char *pResponseID, unsigned int ulResponseIDLen, unsigned char *pSponsorID, unsigned int ulSponsorIDLen, 
	SM9EncMasterPublicKey *pSponsorTempPublicKey, void **phAgreementHandle);
int EVDF_GenerateKeyWithSM9(void *hSessionHandle, void *hAgreementHandle, SM9EncMasterPublicKey *pResponseTempPublicKey, void **phKeyHandle);
int EVDF_GenerateAgreementDataAndKeyWithSM9(void *hSessionHandle, SM9EncMasterPublicKey *pResponsorEncMastPubKey, SM9UserEncPrivateKey *pResponsorPrivateKey, unsigned int uiKeyBits, 
	unsigned char *pResponseID, unsigned int ulResponseIDLen, unsigned char *pSponsorID, unsigned int ulSponsorIDLen, 
	SM9EncMasterPublicKey *pSponsorTempPublicKey, SM9EncMasterPublicKey *pResponseTempPublicKey,void **phKeyHandle);
int SDF_GenerateAgreementDataWithSM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned int uiISKIndex, unsigned int uiKeyBits, 
	unsigned char *pResponseID, unsigned int ulResponseIDLen, unsigned char *pSponsorID, unsigned int ulSponsorIDLen, 
	SM9EncMasterPublicKey *pSponsorTempPublicKey, void **phAgreementHandle);
int SDF_GenerateKeyWithSM9(void *hSessionHandle, void *hAgreementHandle, SM9EncMasterPublicKey *pResponseTempPublicKey, void **phKeyHandle);
int SDF_GenerateAgreementDataAndKeyWithSM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned int uiISKIndex, unsigned int uiKeyBits, 
	unsigned char *pResponseID, unsigned int ulResponseIDLen, unsigned char *pSponsorID, unsigned int ulSponsorIDLen, 
	SM9EncMasterPublicKey *pSponsorTempPublicKey, SM9EncMasterPublicKey *pResponseTempPublicKey,void **phKeyHandle);


/* key calc*/
int EVDF_SignWithMasterEPK_SM9(void *hSessionHandle, SM9SignMasterPublicKey *pPublicKey, SM9UserSignPrivateKey *vk, unsigned char *pucData, 
	unsigned int uiDataLength, SM9Signature *pSignature);
int SDF_InternalSignWithMasterEPK_SM9(void *hSessionHandle, SM9SignMasterPublicKey *pPublicKey, unsigned int uiISKIndex, unsigned char *pucData, 
	unsigned int uiDataLength, SM9Signature *pSignature);
int SDF_InternalSignWithMasterIPK_SM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned int uiISKIndex, unsigned char *pucData, 
	unsigned int uiDataLength, SM9Signature *pSignature);
int SDF_VerifyWithMasterEPK_SM9(void *hSessionHandle, SM9SignMasterPublicKey *pPublicKey, unsigned char *pucUserID, unsigned int uiUserIDLen, 
	unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pSignature);
int SDF_VerifyWithMasterIPK_SM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned char *pucUserID, unsigned int uiUserIDLen, 
	unsigned char *pucData, unsigned int uiDataLength, SM9Signature  *pSignature);
int SDF_EncryptWithMasterEPK_SM9(void *hSessionHandle, SM9EncMasterPublicKey *pPublicKey, unsigned char *pucUserID, unsigned int uiUserIDLen, 
	unsigned int ulAlgID, unsigned char *pIV, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pEncData);
int SDF_EncryptWithMasterIPK_SM9(void *hSessionHandle, unsigned int uiMasterKeyIndex, unsigned char *pucUserID, unsigned int uiUserIDLen, 
	unsigned int ulAlgID, unsigned char *pIV, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pEncData);
int EVDF_DecryptWithUserEncKey_SM9(void *hSessionHandle, SM9UserEncPrivateKey *vk, unsigned char *pucUserID, unsigned int uiUserIDLen, 
	unsigned char *pIV, SM9Cipher *pEncData, unsigned char *pucData, unsigned int *puiDataLength);
int SDF_DecryptWithInternalKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pIV, SM9Cipher *pEncData, 
									unsigned char *pucData, unsigned int *puiDataLength);



#ifdef __cplusplus
};
#endif

#endif  /*__SDF_SM9_H__*/