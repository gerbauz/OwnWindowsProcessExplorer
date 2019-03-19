#ifndef NEWACEDIALOG_H
#define NEWACEDIALOG_H

#include <QDialog>

class FilesystemObject;
class FileDialog;

namespace Ui {
class NewAceDialog;
}

class NewAceDialog : public QDialog
{
    Q_OBJECT

public:
    explicit NewAceDialog(QWidget *parent = nullptr, FilesystemObject *p_file = nullptr);
    ~NewAceDialog();

public slots:
    void slotSaveClicked();
private:
    FileDialog *file_dialog;
    FilesystemObject *file;
    Ui::NewAceDialog *ui;
    unsigned long mask;
    void makeMask();
    void fillTypeBox();
};

#endif // NEWACEDIALOG_H
