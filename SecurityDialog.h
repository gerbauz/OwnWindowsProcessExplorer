#ifndef SECURITYDIALOG_H
#define SECURITYDIALOG_H

#include <QDialog>
#include "ProcessInfoItem.h"

namespace Ui {
class SecurityDialog;
}

class SecurityDialog : public QDialog
{
    Q_OBJECT

public:
    SecurityDialog(QWidget *parent = nullptr, std::shared_ptr<ProcessInfoItem> item = nullptr);
    ~SecurityDialog();

private:
    Ui::SecurityDialog *ui;
    void createUi(const QStringList &header);
    void fillWithPrivileges();
    void fillIntegrityBox();
    void fillPrivileges();
    void showCurrentIntegrity();
    std::shared_ptr<ProcessInfoItem> process_item;

public slots:
    void slotShowContexMenu(QPoint pos);

    void slotEnablePrivelege();
    void slotDisablePrivelege();
};

#endif // SECURITYDIALOG_H
