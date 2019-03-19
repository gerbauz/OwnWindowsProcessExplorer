#include "NewAceDialog.h"
#include "ui_newacedialog.h"
#include "FilesystemObject.h"
#include <QMessageBox>
#include "FileDialog.h"

const DWORD AccessRightArray[] = {
    GENERIC_READ,
    GENERIC_WRITE,
    GENERIC_EXECUTE,
    GENERIC_ALL,
    DELETE,
    READ_CONTROL,
    WRITE_DAC,
    WRITE_OWNER,
    SYNCHRONIZE,
    STANDARD_RIGHTS_REQUIRED,
    STANDARD_RIGHTS_ALL,
    ACTRL_DS_OPEN,
    ACTRL_DS_CREATE_CHILD,
    ACTRL_DS_DELETE_CHILD,
    ACTRL_DS_LIST,
    ACTRL_DS_READ_PROP,
    ACTRL_DS_WRITE_PROP,
    ACTRL_DS_SELF,
    ACTRL_DS_DELETE_TREE,
    ACTRL_DS_LIST_OBJECT,
    ACTRL_DS_CONTROL_ACCESS };

NewAceDialog::NewAceDialog(QWidget *parent, FilesystemObject *p_file) :
    QDialog(parent, Qt::WindowCloseButtonHint),
    file(p_file),
    ui(new Ui::NewAceDialog)

{
    file_dialog = static_cast<FileDialog*>(parent);

    ui->setupUi(this);
    this->fillTypeBox();
    this->setWindowTitle("Edit ACE");
    connect(ui->cancelButton, SIGNAL(clicked()), this, SLOT(close()));
    connect(ui->saveButton, SIGNAL(clicked()), this, SLOT(slotSaveClicked()));


}

void NewAceDialog::makeMask()
{
    mask = 0;

    if (ui->GENERIC_READ_->isChecked()) mask |= AccessRightArray[0];
    if (ui->GENERIC_WRITE_->isChecked()) mask |= AccessRightArray[1];
    if (ui->GENERIC_EXECUTE_->isChecked()) mask |= AccessRightArray[2];
    if (ui->GENERIC_ALL_->isChecked()) mask |= AccessRightArray[3];
    if (ui->DELETE_->isChecked()) mask |= AccessRightArray[4];
    if (ui->READ_CONTROL_->isChecked()) mask |= AccessRightArray[5];
    if (ui->WRITE_DAC_->isChecked()) mask |= AccessRightArray[6];
    if (ui->WRITE_OWNER_->isChecked()) mask |= AccessRightArray[7];
    if (ui->SYNCHRONIZE_->isChecked()) mask |= AccessRightArray[8];
    if (ui->STANDARD_RIGHTS_REQUIRED_->isChecked()) mask |= AccessRightArray[9];
    if (ui->STANDARD_RIGHTS_ALL_->isChecked()) mask |= AccessRightArray[10];
    if (ui->ACTRL_DS_OPEN_->isChecked()) mask |= AccessRightArray[11];
    if (ui->ACTRL_DS_CREATE_CHILD_->isChecked()) mask |= AccessRightArray[12];
    if (ui->ACTRL_DS_DELETE_CHILD_->isChecked()) mask |= AccessRightArray[13];
    if (ui->ACTRL_DS_LIST_->isChecked()) mask |= AccessRightArray[14];
    if (ui->ACTRL_DS_READ_PROP_->isChecked()) mask |= AccessRightArray[15];
    if (ui->ACTRL_DS_SELF_->isChecked()) mask |= AccessRightArray[16];
    if (ui->ACTRL_DS_DELETE_TREE_->isChecked()) mask |= AccessRightArray[17];
    if (ui->ACTRL_DS_LIST_OBJECT_->isChecked()) mask |= AccessRightArray[18];
    if (ui->ACTRL_DS_LIST_OBJECT_->isChecked()) mask |= AccessRightArray[19];
    if (ui->ACTRL_DS_CONTROL_ACCESS_->isChecked()) mask |= AccessRightArray[20];

}

void NewAceDialog::fillTypeBox()
{
    ui->aceTypeBox->addItem(tr("Deny Access"));
    ui->aceTypeBox->addItem(tr("Set Access"));
}

void NewAceDialog::slotSaveClicked()
{
    this->makeMask();
    std::wstring new_owner_name = ui->ownerNameLine->text().toStdWString();
    if (!file->change_acl_info(new_owner_name, mask, ui->aceTypeBox->currentIndex()))
    {
        QMessageBox::warning(this, tr("Error"), tr("Error changing ACE"),  QMessageBox::Ok);
    }
    file_dialog->initializeAclTable();
    this->close();
}

NewAceDialog::~NewAceDialog()
{
    delete ui;
}
