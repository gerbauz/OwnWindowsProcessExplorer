#include "FileDialog.h"
#include "ui_filedialog.h"
#include "AclListModel.h"
#include "FilesystemObject.h"
#include "newacedialog.h"
#include <QMessageBox>

FileDialog::FileDialog(QWidget *parent, QString filename) :
    QDialog(parent, Qt::WindowCloseButtonHint),
    ui(new Ui::FileDialog)
{
    file = new FilesystemObject(filename.toStdWString());
    ui->setupUi(this);
    this->setModal(true);
    model = new AclListModel(file);
    ui->aclList->setModel(model);
    ui->aclList->resizeColumnToContents(0);
    this->setWindowTitle(filename.split("/").last());
    ui->ownerNameLine->setText(QString::fromStdWString(file->owner));
    this->fillIntegrityBox();

    connect(ui->intLvlBox, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), [this](int index)
    {
        if (!this->file->change_integrity_level(index))
        {
            QMessageBox::warning(this, tr("Error"), tr("Error changing integrity level"),  QMessageBox::Ok);
        }
        this->showCurrentIntegrity();
    });

    connect(ui->saveButton, &QPushButton::clicked, [this](bool)
    {
        std::wstring new_owner = ui->ownerNameLine->text().toStdWString();
        if (!this->file->change_owner(new_owner))
        {
            QMessageBox::warning(this, tr("Error"), tr("Error changing owner"),  QMessageBox::Ok);
        }
        this->file->fill_owner();
        ui->ownerNameLine->setText(QString::fromStdWString(file->owner));
    });

    connect(ui->editButton, SIGNAL(clicked()), this, SLOT(slotOpenEditDialog()));

}

void FileDialog::slotOpenEditDialog()
{
    NewAceDialog *ace_dialog = new NewAceDialog(this, file);
    ace_dialog->show();
}

void FileDialog::fillIntegrityBox()
{
    ui->intLvlBox->addItem(tr("Untrusted"));
    ui->intLvlBox->addItem(tr("Low Integrity"));
    ui->intLvlBox->addItem(tr("Medium Integrity"));
    ui->intLvlBox->addItem(tr("High Integrity"));
    ui->intLvlBox->addItem(tr("System Integrity"));
    this->showCurrentIntegrity();
}

void FileDialog::showCurrentIntegrity()
{
    file->fill_integrity_level();
    QString current_int_lvl = QString::fromStdWString(file->integrity_level);
    if (current_int_lvl == "Untrusted")
        ui->intLvlBox->setCurrentIndex(0);
    else if (current_int_lvl == "Low Integrity")
        ui->intLvlBox->setCurrentIndex(1);
    else if (current_int_lvl == "Medium Integrity")
        ui->intLvlBox->setCurrentIndex(2);
    else if (current_int_lvl == "High Integrity")
        ui->intLvlBox->setCurrentIndex(3);
    else
        ui->intLvlBox->setCurrentIndex(4);
}

FileDialog::~FileDialog()
{
    delete file;
    delete model;
    delete ui;
}

void FileDialog::initializeAclTable()
{
    delete model;
    model = new AclListModel(file);
    ui->aclList->setModel(model);
    ui->aclList->resizeColumnToContents(0);
}
