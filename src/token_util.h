#pragma once

#include <QObject>
#include <QDateTime>
#include <QVariant>
#include <QByteArray>
#include <QUuid>
#include "./token_global.h"

namespace QToken {

//!
//! \brief The eTokSecretReturn enum
//!
enum eTokSecretReturn {
    VALID             = 0,
    PAYLOAD_INVALID   = 1,
    USER_NOT_VALID    = 2,
    USER_HASNT_SECRET = 3,
    RECOVERY_ERROR    = 4
};

//!
//! \brief The eTokAlgorithm enum
//!
enum eTokAlgorithm
{
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    PS256,
    PS384,
    PS512,
    EdDSA
};

//!
//! \brief The eTokType enum
//!
enum eTokType {
    JWT=0
};

//!
//! \brief The Token struct
//!
struct Q_TOKEN_EXPORT Token{
public:
    QUuid uuid;
    eTokAlgorithm algorithm=HS256;
    QByteArray secret;
    QByteArray requestPath;
    QHash<QByteArray,QByteArray> requestHeader;
    QHash<QByteArray,QByteArray> requestParamter;
    QByteArray token;
    QToken::eTokType eTokType=QToken::JWT;
    QByteArray tokenScope;
    QByteArray tokenHeader;
    QByteArray tokenPayload;
    QByteArray tokenSignature;
    QDateTime tokenIat;
    QDateTime tokenExp;
    QVariantHash tokenPayLoad;
    bool tokenActive=true;

    //!
    //! \brief tokenMd5
    //! \return
    //!
    QByteArray tokenMd5() const;

    //!
    //! \brief toMd5
    //! \param bytes
    //! \return
    //!
    static const QByteArray toMd5(const QByteArray &bytes);

    //!
    //! \brief toReturnHash
    //! \return
    //!
    QVariantHash toReturnHash() const;
};

//!
//! \brief The TokenUtil class
//!
class Q_TOKEN_EXPORT TokenUtil : public QObject
{
    Q_OBJECT
public:

    Q_ENUM(eTokSecretReturn)
    Q_ENUM(eTokAlgorithm)
    Q_ENUM(eTokType)

    //!
    //! \brief TokenUtil
    //! \param parent
    //!
    explicit TokenUtil(QObject *parent = nullptr);

    //!
    //! \brief TokenUtil
    //! \param secret
    //! \param parent
    //!
    explicit TokenUtil(const QByteArray&secret, QObject *parent = nullptr);

    //!
    //! \brief TokenUtil
    //! \param secret
    //! \param payload
    //! \param parent
    //!
    explicit TokenUtil(const QByteArray&secret, const QHash<QByteArray,QByteArray>&payload, QObject *parent = nullptr);

    //!
    //! \brief TokenUtil
    //! \param secret
    //! \param payload
    //! \param algorithm
    //! \param parent
    //!
    explicit TokenUtil(const QByteArray&secret, const QHash<QByteArray,QByteArray>&payload, const eTokAlgorithm&algorithm, QObject *parent = nullptr);

    //!
    //! \brief TokenUtil
    //! \param secret
    //! \param payload
    //! \param algorithm
    //! \param expires_in
    //! \param parent
    //!
    explicit TokenUtil(const QByteArray&secret, const QHash<QByteArray,QByteArray>&payload, const eTokAlgorithm&algorithm, const QDateTime&expires_in, QObject *parent = nullptr);

    //!
    //! \brief TokenUtil
    //!
    ~TokenUtil();

    //!
    //! \brief token
    //! \return
    //!
    QByteArray &token() const;

    //!
    //! \brief setToken
    //! \param value
    //! \return
    //!
    TokenUtil &setToken(const QByteArray &value);

    //!
    //! \brief generateToken
    //! \return
    //!
    Token generateToken();

    //!
    //! \brief generateToken
    //! \param secre
    //! \return
    //!
    Token generateToken(const QByteArray&secre);

    //!
    //! \brief generateToken
    //! \param secre
    //! \param payload
    //! \return
    //!
    Token generateToken(const QByteArray&secre, const QHash<QByteArray,QByteArray> &payload);

    //!
    //! \brief generateToken
    //! \param secre
    //! \param payload
    //! \param algorithm
    //! \return
    //!
    Token generateToken(const QByteArray&secre, const QHash<QByteArray,QByteArray> &payload, const eTokAlgorithm&algorithm);

    //!
    //! \brief generateToken
    //! \param secret
    //! \param payload
    //! \param algorithm
    //! \param expires_in
    //! \return
    //!
    Token generateToken(const QByteArray &secret, const QHash<QByteArray, QByteArray> &payload, const eTokAlgorithm&algorithm, const QDateTime &expires_in);

    //!
    //! \brief isTokenValid
    //! \return
    //!
    bool isTokenValid();

    //!
    //! \brief isExpired
    //! \return
    //!
    bool isExpired();

    //!
    //! \brief supportedAlgorithm
    //! \return
    //!
    static const QStringList &supportedAlgorithm();

    //!
    //! \brief lastError
    //! \return
    //!
    QVariant &lastError() const;

    //!
    //! \brief setLastError
    //! \param value
    //! \return
    //!
    bool setLastError(const QVariant &value);

    //!
    //! \brief algorithmType
    //! \return
    //!
    static const QHash<QByteArray, eTokAlgorithm> &algorithmType();

    //!
    //! \brief AlgorithmStr
    //! \return
    //!
    static const QHash<eTokAlgorithm, QByteArray> &algorithmStr();


    //!
    //! \brief algorithm
    //! \param alg
    //! \return
    //!
    static eTokAlgorithm algorithm(const QByteArray&alg);

    //!
    //! \brief algorithmToStr
    //! \param algorithm
    //! \return
    //!
    static const QByteArray &algorithmToStr(const eTokAlgorithm&algorithm);

    //!
    //! \brief eTokTypeToStr
    //! \param type
    //! \return
    //!
    static const QByteArray eTokTypeToStr(const eTokType&type);

    //!
    //! \brief isValidAlgorithm
    //! \param alg
    //! \return
    //!
    static bool isValidAlgorithm(const QByteArray&alg);

    //!
    //! \brief readFromToken
    //! \param token
    //! \return
    //!
    static Token readFromToken(const QByteArray&token);

    //!
    //! \brief verifyToken
    //! \param token
    //! \param secret
    //! \return
    //!
    static bool verifyToken(const QByteArray&token, const QByteArray&secret);

private:
    void*p=nullptr;
};

}
