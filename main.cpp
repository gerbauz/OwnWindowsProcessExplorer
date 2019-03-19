#include "MainWindow.h"
#include "SecurityDialog.h"
//#include "processlistmodel.h"
#include <QApplication>
//#include <QTreeView>
#include <QTextCodec>
#include "ProcessInfoItem.h"

int main(int argc, char *argv[])
{
    int id = qRegisterMetaType<std::shared_ptr<ProcessInfoItem>>();
    QTextCodec* codec = QTextCodec::codecForName("UTF-8");
    QTextCodec::setCodecForLocale(codec);
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
