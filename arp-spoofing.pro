TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -pthread

SOURCES += \
        arphdr.cpp \
        ethhdr.cpp \
        ip.cpp \
        iphdr.cpp \
        mac.cpp \
        main.cpp

HEADERS += \
        arphdr.h \
        ethhdr.h \
        ip.h \
        iphdr.h \
        mac.h
