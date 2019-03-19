#ifndef FILEDIALOG_H
#define FILEDIALOG_H

#include <QDialog>

class AclListModel;
class FilesystemObject;

namespace Ui {
class FileDialog;
}

class FileDialog : public QDialog
{
    Q_OBJECT

public:
    FileDialog(QWidget *parent = nullptr, QString filename = nullptr);
    void initializeAclTable();
    ~FileDialog();

public slots:
    void slotOpenEditDialog();

private:
    Ui::FileDialog *ui;
    AclListModel *model;
    FilesystemObject *file;
    void fillIntegrityBox();
    void showCurrentIntegrity();

};

#endif // FILEDIALOG_H
