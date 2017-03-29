/*
   pbkdf2test - find inetrations for PBKDF2
   Copyright (C) 2017 Matthias Fehring <kontakt@buschmann23.de>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <QCoreApplication>
#include <QCommandLineOption>
#include <QCommandLineParser>
#include <QByteArray>
#include <QCryptographicHash>
#include <QFile>
#include <QUuid>
#include <QMessageAuthenticationCode>
#include <QByteArrayList>
#include <QDateTime>
#include <QStringList>
#include <stdio.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <limits>
#include <algorithm>

#include <QtDebug>

/*!
 * \brief Generates random data.
 */
static QByteArray genRand(qint64 size, bool b64 = true)
{
    QByteArray salt;

    QFile random(QStringLiteral("/dev/urandom"));
    if (!random.open(QIODevice::ReadOnly)) {
        if (b64) {
            salt = QUuid::createUuid().toByteArray().toBase64();
        } else {
            salt = QUuid::createUuid().toByteArray();
        }
    } else {
        if (b64) {
            salt = random.read(size).toBase64();
        } else {
            salt = random.read(size);
        }
    }

    return salt;
}

/*!
 * \brief Implement PBKDF2 password hashing.
 *
 * Derived from Cutelyst at https://github.com/cutelyst/cutelyst/blob/master/Cutelyst/Plugins/Authentication/credentialpassword.cpp
 *
 * \author Daniel Nicoletti <dantti12@gmail.com>
 * \date 2013-2015
 * \copyright GNU General Public License, Version 2
 * \return
 */
static QByteArray pbkdf2Cutelyst(QCryptographicHash::Algorithm method, const QByteArray &password, const QByteArray &salt, int rounds, int keyLength)
{
    QByteArray key;
    key.reserve(keyLength);

    int saltSize = salt.size();
    QByteArray asalt = salt;
    asalt.resize(saltSize + 4);

    QByteArray d1, obuf;

    QMessageAuthenticationCode code(method, password);

    for (int count = 1, remainingBytes = keyLength; remainingBytes > 0; ++count) {
        asalt[saltSize + 0] = static_cast<char>((count >> 24) & 0xff);
        asalt[saltSize + 1] = static_cast<char>((count >> 16) & 0xff);
        asalt[saltSize + 2] = static_cast<char>((count >> 8) & 0xff);
        asalt[saltSize + 3] = static_cast<char>(count & 0xff);

        code.reset();
        code.addData(asalt);
        obuf = d1 = code.result();

        for (int i = 1; i < rounds; ++i) {
            code.reset();
            code.addData(d1);
            d1 = code.result();
            auto it = obuf.begin();
            auto d1It = d1.cbegin();
            while (d1It != d1.cend()) {
                *it = *it ^ *d1It;
                ++it;
                ++d1It;
            }
        }

        key.append(obuf);
        remainingBytes -= obuf.size();
    }

    key = key.mid(0, keyLength);
    return key;
}

const EVP_MD *openSSLDigest(const QString &d)
{
    if(d.compare(QLatin1String("MD4"), Qt::CaseInsensitive) == 0) {
        return EVP_md4();
    } else if (d.compare(QLatin1String("MD5"), Qt::CaseInsensitive) == 0) {
        return EVP_md5();
    } else if (d.compare(QLatin1String("SHA-1"), Qt::CaseInsensitive) == 0) {
        return EVP_sha1();
    } else if (d.compare(QLatin1String("SHA-224"), Qt::CaseInsensitive) == 0) {
        return EVP_sha224();
    } else if (d.compare(QLatin1String("SHA-256"), Qt::CaseInsensitive) == 0) {
        qDebug() << "SHA256";
        return EVP_sha256();
    } else if (d.compare(QLatin1String("SHA-384"), Qt::CaseInsensitive) == 0) {
        return EVP_sha384();
    } else if (d.compare(QLatin1String("SHA-512"), Qt::CaseInsensitive) == 0) {
        return EVP_sha512();
    } else if (d.compare(QLatin1String("Whirlpool"), Qt::CaseInsensitive) == 0) {
        return EVP_whirlpool();
    } else if (d.compare(QLatin1String("RIPEMD-160"), Qt::CaseInsensitive) == 0) {
        return EVP_ripemd160();
    } else {
        return nullptr;
    }
}

QCryptographicHash::Algorithm cutelystDigest(const QString &d)
{
    if(d.compare(QLatin1String("MD4"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Md4;
    } else if (d.compare(QLatin1String("MD5"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Md5;
    } else if (d.compare(QLatin1String("SHA-1"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Sha1;
    } else if (d.compare(QLatin1String("SHA-224"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Sha224;
    } else if (d.compare(QLatin1String("SHA-384"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Sha384;
    } else if (d.compare(QLatin1String("SHA-512"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Sha512;
    } else if (d.compare(QLatin1String("SHA3-224"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Sha3_224;
    } else if (d.compare(QLatin1String("SHA3-256"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Sha3_256;
    } else if (d.compare(QLatin1String("SHA3-384"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Sha3_384;
    } else if (d.compare(QLatin1String("SHA3-256"), Qt::CaseInsensitive) == 0) {
        return QCryptographicHash::Sha3_512;
    } else {
        return QCryptographicHash::Sha256;
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setOrganizationName(QStringLiteral("Buschtrommel"));
    app.setOrganizationName(QStringLiteral("buschmann23.de"));
    app.setApplicationName(QStringLiteral("pbkdf2test"));
    app.setApplicationVersion(QStringLiteral(PBKDF2TEST_VERSION));

    const QStringList supMdCutelyst = {
        QStringLiteral("MD4"), QStringLiteral("MD5"), QStringLiteral("SHA-1"), QStringLiteral("SHA-224"), QStringLiteral("SHA-256"), QStringLiteral("SHA-384"), QStringLiteral("SHA-512"),
        QStringLiteral("SHA3-224"), QStringLiteral("SHA3-256"), QStringLiteral("SHA3-384"), QStringLiteral("SHA3-512")
    };

    const QStringList supMdOpenssl = {
        QStringLiteral("MD4"), QStringLiteral("MD5"), QStringLiteral("SHA-1"), QStringLiteral("SHA-224"), QStringLiteral("SHA-256"), QStringLiteral("SHA-384"), QStringLiteral("SHA-512"),
        QStringLiteral("Whirlpool"), QStringLiteral("RIPEMD-160")
    };


    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();

    parser.setApplicationDescription(app.applicationName() + QStringLiteral(" version ") + app.applicationVersion() + QStringLiteral(" Copyright (C) 2017 Matthias Fehring <kontakt@buschmann23.de>\n") + app.applicationName() + QStringLiteral(" comes with ABSOLUTELY NO WARRANTY.\nThis is free software, and you are welcome to redistribute it under the conditions of\nthe GNU General Public License, Version 2."));

    QCommandLineOption i(QStringList({QStringLiteral("implementation"), QStringLiteral("i")}), QStringLiteral("The implementation that should be used. Currently available: OpenSSL, Cutelyst. Default: OpenSSL"), QStringLiteral("impl"), QStringLiteral("OpenSSL"));
    parser.addOption(i);

    QCommandLineOption d(QStringList({QStringLiteral("digest"), QStringLiteral("d")}), QStringLiteral("The message digest function to use in the derivation. Default: SHA-256\n\nSuported by OpenSSL: %1\n\nSupported by Cutelyst: %2").arg(supMdOpenssl.join(QStringLiteral(", ")), supMdCutelyst.join(QStringLiteral(", "))), QStringLiteral("digest"), QStringLiteral("SHA-256"));
    parser.addOption(d);

    QCommandLineOption sl(QStringList({QStringLiteral("salt-length"), QStringLiteral("sl")}), QStringLiteral("Length of the salt to use in bytes. Default: 24"), QStringLiteral("slength"), QStringLiteral("24"));
    parser.addOption(sl);

    QCommandLineOption kl(QStringList({QStringLiteral("key-length"), QStringLiteral("kl")}), QStringLiteral("Length of the derived key in bytes. Default: 18"), QStringLiteral("klength"), QStringLiteral("18"));
    parser.addOption(kl);

    QCommandLineOption tTime(QStringList({QStringLiteral("target-time"), QStringLiteral("t")}), QStringLiteral("Time the password encryption should use approximately in milliseconds. Default: 500"), QStringLiteral("ms"), QStringLiteral("500"));
    parser.addOption(tTime);

    parser.process(app);

    const QString impl = parser.value(i);
    const QStringList supImp = {
        QStringLiteral("openssl"), QStringLiteral("cutelyst")
    };
    if (!supImp.contains(impl, Qt::CaseInsensitive)) {
        printf("%s is not a supported implementation.\n", qUtf8Printable(impl));
        return 1;
    }

    const QString md = parser.value(d);

    if (impl.compare(QLatin1String("cutelyst"), Qt::CaseInsensitive) == 0) {
        if (!supMdCutelyst.contains(md, Qt::CaseInsensitive)) {
            printf("%s is not supported by Cutelyst.\n", qUtf8Printable(md));
            return 1;
        }
    }

    if (impl.compare(QLatin1String("openssl"), Qt::CaseInsensitive) == 0) {
        if (!supMdOpenssl.contains(md, Qt::CaseInsensitive)) {
            printf("%s is not suppoerted by OpenSSL.\n", qUtf8Printable(md));
            return 1;
        }
    }


    const int saltLength = abs(parser.value(sl).toInt());
    const int keyLength = abs(parser.value(kl).toInt());
    const int targetTime = abs(parser.value(tTime).toInt());
    const int testCount = 100;
    const int rounds = 30000;

    printf("Implementation:        %s\n", qUtf8Printable(impl));
    printf("Message digest:        %s\n", qUtf8Printable(md));
    printf("Salt size:             %u bytes\n", saltLength);
    printf("Key length:            %u bytes\n", keyLength);
    printf("Target time:           %u ms\n", targetTime);
    printf("Generating %u PBKDF2 hashes with %u iterations.\n", testCount, rounds);
    printf("--------------------------------------------------------------\n");

    QByteArrayList passwords;
    QByteArrayList salts;

    for (int i = 0; i < testCount; ++i) {
        passwords.append(genRand(10));
        salts.append(genRand(saltLength));
    }

    int totalTime = 0;
    int min = std::numeric_limits<int>::max();
    int max = std::numeric_limits<int>::min();
    int avg = 0;

    const EVP_MD *ossld = openSSLDigest(md);
    const QCryptographicHash::Algorithm cld = cutelystDigest(md);

    for (int i = 0; i < testCount; ++i) {
        const QByteArray pw = passwords.at(i);
        const QByteArray salt = salts.at(i);
        QDateTime t;
        int tt = 0;

        if (impl == QLatin1String("cutelyst")) {

            t = QDateTime::currentDateTime();
            pbkdf2Cutelyst(cld, pw, salt, rounds, keyLength);
            tt = t.msecsTo(QDateTime::currentDateTime());

        } else if (impl == QLatin1String("openssl")) {

            unsigned char *out;
            out = (unsigned char *) malloc(sizeof(unsigned char) * keyLength);
            unsigned char *usalt = (unsigned char*)(salt.data());
            int usaltsize = salt.size();
            const char *ccpw = pw.constData();
            int ccpwsize = pw.size();
            t = QDateTime::currentDateTime();
            PKCS5_PBKDF2_HMAC(ccpw, ccpwsize, usalt, usaltsize, rounds, ossld, keyLength, out);
            tt = t.msecsTo(QDateTime::currentDateTime());
            free(out);
        }
        totalTime += tt;
        min = std::min(min, tt);
        max = std::max(max, tt);
    }

    avg = (totalTime/testCount);

    printf("Total time:            %4u ms\n", totalTime);
    printf("Minimum time:          %4u ms\n", min);
    printf("Maximum time:          %4u ms\n", max);
    printf("Average time:          %4u ms\n", avg);
    printf("Proposed iterations:   %u\n", ((targetTime/avg) * rounds));

    return 0;
}
