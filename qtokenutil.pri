QT += core
QT += sql

QTREFORCE_QJWTUTIL=true
DEFINES+=QTREFORCE_QJWTUTIL

HEADERS += \
    $$PWD/src/token_global.h \
    $$PWD/src/token_util.h

SOURCES += \
    $$PWD/src/token_util.cpp
