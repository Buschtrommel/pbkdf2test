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
#include <stdio.h>

/*!
 * \brief Generates random data.
 */
static QByteArray genRand(qint64 size)
{
    QByteArray salt;

    QFile random(QStringLiteral("/dev/urandom"));
    if (!random.open(QIODevice::ReadOnly)) {
        salt = QUuid::createUuid().toByteArray().toBase64();
    } else {
        salt = random.read(size).toBase64();
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
static QByteArray pbkdf2(QCryptographicHash::Algorithm method, const QByteArray &password, const QByteArray &salt, int rounds, int keyLength)
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

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setOrganizationName(QStringLiteral("Buschtrommel"));
    app.setOrganizationName(QStringLiteral("buschmann23.de"));
    app.setApplicationName(QStringLiteral("pbkdf2test"));
    app.setApplicationVersion(QStringLiteral(PBKDF2TEST_VERSION));


    QByteArrayList passwords;
    QByteArrayList salts;

    for (int i = 0; i < 10; ++i) {
        passwords.append(genRand(10));
        salts.append(genRand(24));
    }

    qint64 totalTime = 0;
    int rounds = 0;

    while ((totalTime == 0) || ((totalTime < 480) || (totalTime > 520))) {
        rounds += 5000;
        for (int i = 0; i < passwords.size(); ++i) {
            const QByteArray pw = passwords.at(i);
            const QByteArray salt = salts.at(i);
            const qint64 a = QDateTime::currentMSecsSinceEpoch();
            pbkdf2(QCryptographicHash::Sha256, pw, salt, rounds, 18);
            const qint64 b = QDateTime::currentMSecsSinceEpoch();
            totalTime += (b-a);
        }
        totalTime = (totalTime/passwords.size());
        printf("Rounds: %i Time: %i\n", rounds, totalTime);
    }
}
