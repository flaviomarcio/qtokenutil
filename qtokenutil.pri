QT += core
QT += sql

QTREFORCE_QTOKENUTIL=true
DEFINES+=QTREFORCE_QTOKENUTIL

HEADERS += \
    $$PWD/src/token_global.h \
    $$PWD/src/token_util.h

SOURCES += \
    $$PWD/src/token_util.cpp
