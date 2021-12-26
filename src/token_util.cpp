#include "./token_util.h"
//#include "./qstm_macro.h"
#include "../../qjsonwebtoken/qjsonwebtoken.h"
#include <QDateTime>

namespace QToken {

auto makeAlgorithmType()
{
    QHash<QByteArray,eTokAlgorithm> __return;
    __return[QByteArrayLiteral(QT_STRINGIFY(HS256)).toLower()]=HS256;
    __return[QByteArrayLiteral(QT_STRINGIFY(HS384)).toLower()]=HS384;
    __return[QByteArrayLiteral(QT_STRINGIFY(HS512)).toLower()]=HS512;
    __return[QByteArrayLiteral(QT_STRINGIFY(RS256)).toLower()]=RS256;
    __return[QByteArrayLiteral(QT_STRINGIFY(RS384)).toLower()]=RS384;
    __return[QByteArrayLiteral(QT_STRINGIFY(RS512)).toLower()]=RS512;
    __return[QByteArrayLiteral(QT_STRINGIFY(ES256)).toLower()]=ES256;
    __return[QByteArrayLiteral(QT_STRINGIFY(ES384)).toLower()]=ES384;
    __return[QByteArrayLiteral(QT_STRINGIFY(ES512)).toLower()]=ES512;
    __return[QByteArrayLiteral(QT_STRINGIFY(PS256)).toLower()]=PS256;
    __return[QByteArrayLiteral(QT_STRINGIFY(PS384)).toLower()]=PS384;
    __return[QByteArrayLiteral(QT_STRINGIFY(PS512)).toLower()]=PS512;
    __return[QByteArrayLiteral(QT_STRINGIFY(EdDSA)).toLower()]=EdDSA;

    return __return;
}

auto makeJwtAlgorithmStr()
{
    QHash<eTokAlgorithm, QByteArray> __return;
    __return[HS256]=QByteArray(QT_STRINGIFY(HS256)).toLower();
    __return[HS384]=QByteArray(QT_STRINGIFY(HS384)).toLower();
    __return[HS512]=QByteArray(QT_STRINGIFY(HS512)).toLower();
    __return[RS256]=QByteArray(QT_STRINGIFY(RS256)).toLower();
    __return[RS384]=QByteArray(QT_STRINGIFY(RS384)).toLower();
    __return[RS512]=QByteArray(QT_STRINGIFY(RS512)).toLower();
    __return[ES256]=QByteArray(QT_STRINGIFY(ES256)).toLower();
    __return[ES384]=QByteArray(QT_STRINGIFY(ES384)).toLower();
    __return[ES512]=QByteArray(QT_STRINGIFY(ES512)).toLower();
    __return[PS256]=QByteArray(QT_STRINGIFY(PS256)).toLower();
    __return[PS384]=QByteArray(QT_STRINGIFY(PS384)).toLower();
    __return[PS512]=QByteArray(QT_STRINGIFY(PS512)).toLower();
    __return[EdDSA]=QByteArray(QT_STRINGIFY(EdDSA)).toLower();
    return __return;
}

static const auto jwtAlgorithmType=makeAlgorithmType();
static auto jwtAlgorithmStr=makeJwtAlgorithmStr();

static const auto claim_exp = QByteArrayLiteral("exp");
static const auto claim_iss = QByteArrayLiteral("iss");
static const auto claim_iat = QByteArrayLiteral("iat");
static const auto claim_aud = QByteArrayLiteral("aud");
static const auto claim_sub = QByteArrayLiteral("sub");
static const auto claim_tsp = QByteArrayLiteral("tsp");


auto makeClaims(){
    return QVector<QByteArray>{claim_exp , claim_iss, claim_iat, claim_aud, claim_sub, claim_tsp};
}
static const auto claims = makeClaims();
static const auto supportedAlgorithms=QJsonWebToken::supportedAlgorithms();


#define dPvt()\
auto&p = *reinterpret_cast<TokenUtilPvt*>(this->p)

class TokenUtilPvt{
public:
    QDateTime expires_in;
    QVariant lastError;
    QHash<QByteArray, QByteArray> payload;
    QByteArray secret;
    QByteArray token;
    eTokAlgorithm algorithm=HS256;
    explicit TokenUtilPvt(){
    }

    virtual ~TokenUtilPvt(){
    }
};

QByteArray Token::tokenMd5()const
{
    return Token::toMd5(this->token);
}

const QByteArray Token::toMd5(const QByteArray&bytes)
{
    return QCryptographicHash::hash(bytes, QCryptographicHash::Md5).toHex();
}

QVariantHash Token::toReturnHash()const
{
    return QVariantHash
        {
            {QByteArrayLiteral("token"),this->token},
            {QByteArrayLiteral("iat"),this->tokenIat},
            {QByteArrayLiteral("exp"),this->tokenExp}
        };
}

TokenUtil::TokenUtil(QObject *parent) : QObject(parent)
{
    this->p=new TokenUtilPvt();
}

TokenUtil::TokenUtil(const QByteArray &secret, QObject *parent) : QObject(parent)
{
    this->p=new TokenUtilPvt();
    dPvt();
    p.secret=secret;
}

TokenUtil::TokenUtil(const QByteArray &secret, const QHash<QByteArray, QByteArray> &payload, QObject *parent):QObject(parent)
{
    this->p=new TokenUtilPvt();
    dPvt();
    p.secret=secret;
    p.payload=payload;
}

TokenUtil::TokenUtil(const QByteArray &secret, const QHash<QByteArray, QByteArray> &payload, const eTokAlgorithm &algorithm, QObject *parent):QObject(parent)
{
    this->p=new TokenUtilPvt();
    dPvt();
    p.secret=secret;
    p.payload=payload;
    p.algorithm=algorithm;
}

TokenUtil::TokenUtil(const QByteArray &secret, const QHash<QByteArray, QByteArray> &payload, const eTokAlgorithm &algorithm, const QDateTime &expires_in, QObject *parent):QObject(parent)
{
    this->p=new TokenUtilPvt();
    dPvt();
    p.secret=secret;
    p.payload=payload;
    p.algorithm=algorithm;
    p.expires_in=expires_in;
}

TokenUtil::~TokenUtil()
{
    dPvt();
    delete&p;
}

bool TokenUtil::isTokenValid()
{
    dPvt();
    if (p.token.simplified().isEmpty())
        return this->setLastError(tr("No avaliable token"));

    auto tokenParts = p.token.split('.');
    if (tokenParts.count() != 3)
        return this->setLastError(tr("ERROR : token must have the format xxxx.yyyyy.zzzzz"));
    auto token = QJsonWebToken::fromTokenAndSecret(p.token, p.secret);
    return token.isValid();
}

bool TokenUtil::isExpired()
{
    dPvt();
    if (!p.payload.isEmpty()){
        auto claimEXP = p.payload.value(claim_exp).toLongLong();
        auto currentdate = QDateTime::currentDateTime().toSecsSinceEpoch();
        return  (claimEXP < currentdate);
    }
    return true;
}

const QStringList&TokenUtil::supportedAlgorithm()
{
    return supportedAlgorithms;
}

QVariant&TokenUtil::lastError() const
{
    dPvt();
    return p.lastError;
}

bool TokenUtil::setLastError(const QVariant&value)
{
    dPvt();
    auto err=value.toString().trimmed();
    p.lastError = err.isEmpty()?QVariant():err;
    return p.lastError.isValid();
}

const QHash<QByteArray, eTokAlgorithm> &TokenUtil::algorithmType()
{
    return jwtAlgorithmType;
}

const QHash<eTokAlgorithm, QByteArray> &TokenUtil::algorithmStr()
{
    return jwtAlgorithmStr;
}

eTokAlgorithm TokenUtil::algorithm(const QByteArray&alg)
{
    auto sAlg=alg.trimmed().toLower();
    auto&map=TokenUtil::algorithmType();
    if(!map.contains(sAlg))
        return HS256;
    return map.value(sAlg);
}

const QByteArray&TokenUtil::algorithmToStr(const eTokAlgorithm &algorithm)
{
    return jwtAlgorithmStr[algorithm];
}

const QByteArray TokenUtil::eTokTypeToStr(const eTokType &type)
{
    if(type==JWT)
        return QByteArrayLiteral("JWT");
    return QByteArrayLiteral("???");
}

bool TokenUtil::isValidAlgorithm(const QByteArray &alg)
{
    auto sAlg=alg.trimmed().toLower();
    auto&map=TokenUtil::algorithmType();
    if(map.contains(sAlg))
        return true;
    return false;
}

Token TokenUtil::readFromToken(const QByteArray &token)
{
    QJsonWebToken m_jwtObj;
    m_jwtObj.setToken(token);
    Token __returnToken;
    __returnToken.eTokType=JWT;
    __returnToken.algorithm=TokenUtil::algorithmType().value(m_jwtObj.getAlgorithmStr().toLower().toUtf8());
    __returnToken.secret.clear();
    __returnToken.tokenPayLoad=m_jwtObj.getPayloadJDoc().object().toVariantHash();
    __returnToken.tokenScope=__returnToken.tokenPayLoad.value(QByteArrayLiteral("scope")).toByteArray();
    __returnToken.tokenIat.setSecsSinceEpoch(__returnToken.tokenPayLoad.value(QByteArrayLiteral("iat")).toLongLong());
    __returnToken.tokenExp.setSecsSinceEpoch(__returnToken.tokenPayLoad.value(QByteArrayLiteral("exp")).toLongLong());
    return __returnToken;
}

bool TokenUtil::verifyToken(const QByteArray &token, const QByteArray &secret)
{
    auto m_jwtObj = QJsonWebToken::fromTokenAndSecret(QString::fromUtf8(token), QByteArray(secret));
    return m_jwtObj.isValid();
}

QByteArray&TokenUtil::token() const
{
    dPvt();
    return p.token;
}

TokenUtil&TokenUtil::setToken(const QByteArray &value)
{
    dPvt();
    p.token = value;
    return*this;
}

Token TokenUtil::generateToken()
{
    dPvt();
    return this->generateToken(p.secret, p.payload, p.algorithm, p.expires_in);
}

Token TokenUtil::generateToken(const QByteArray &secre)
{
    dPvt();
    return this->generateToken(secre, p.payload, p.algorithm, p.expires_in);
}

Token TokenUtil::generateToken(const QByteArray &secre, const QHash<QByteArray, QByteArray> &payload)
{
    dPvt();
    return this->generateToken(secre, payload, p.algorithm, p.expires_in);
}

Token TokenUtil::generateToken(const QByteArray &secre, const QHash<QByteArray, QByteArray> &payload, const eTokAlgorithm &algorithm)
{
    dPvt();
    return this->generateToken(secre, payload, algorithm, p.expires_in);
}

Token TokenUtil::generateToken(const QByteArray&secret, const QHash<QByteArray, QByteArray> &payload, const eTokAlgorithm &algorithm, const QDateTime &expires_in)
{
    dPvt();
    Token token;
    token.eTokType=eTokType::JWT;
    token.tokenIat=QDateTime::currentDateTime().toLocalTime();
    token.tokenExp=expires_in;

    QJsonWebToken m_jwtObj;
    m_jwtObj.setAlgorithmStr(jwtAlgorithmStr.value(algorithm).toUpper());
    m_jwtObj.setSecret(secret);

    auto tokenPayLoad=payload;
    tokenPayLoad[claim_iat]=QString::number(token.tokenIat.toSecsSinceEpoch()).toUtf8();
    tokenPayLoad[claim_exp]=QString::number(token.tokenExp.toSecsSinceEpoch()).toUtf8();

    QHashIterator<QByteArray,QByteArray> i(tokenPayLoad);
    while (i.hasNext()) {
        i.next();
        const auto&key=i.key();
        const auto&value=i.value();
        m_jwtObj.appendClaim(key, value);
    }

    p.token=m_jwtObj.getToken();

    token.tokenHeader=m_jwtObj.getHeaderJDoc().toJson(QJsonDocument::Compact);
    token.tokenPayload=m_jwtObj.getPayloadJDoc().toJson(QJsonDocument::Compact);
    token.tokenSignature=m_jwtObj.getSignatureBase64();
    token.token=p.token;
    return token;
}


}
