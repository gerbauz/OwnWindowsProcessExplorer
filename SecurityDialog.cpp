#include "SecurityDialog.h"
#include "ui_securitydialog.h"
#include "ProcessInfoItem.h"

#include <QTableWidgetItem>
#include <QMenu>
#include <QMessageBox>

namespace
{

QString convertToQString(std::wstring str)
{
    return QString::fromStdWString(str);
}


QString convertToQString(std::string str)
{
    return QString::fromStdString(str);
}


QString convertToQString(DWORD val)
{
    return QString::number(val);
}

QString convertToQString(int val)
{
    return QString::number(val);
}

QString convertToQString(bool val)
{
    if (true == val)
        return "YES";
    else
        return "NO";
}

}

SecurityDialog::SecurityDialog(QWidget *parent, std::shared_ptr<ProcessInfoItem> item) :
    QDialog(parent, Qt::WindowCloseButtonHint),
    ui(new Ui::SecurityDialog)
{
    process_item = std::move(item);

    ui->setupUi(this);

    this->setModal(true);

    this->setWindowTitle(convertToQString(process_item->process_name_));

    this->createUi(QStringList() <<tr("Privilege") << tr("Status"));

    this->fillIntegrityBox();

    this->fillPrivileges();

    connect(ui->privilegeTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotShowContexMenu(QPoint)));
    connect(ui->okButton, SIGNAL(clicked()), this, SLOT(close()));
    connect(ui->intLvlBox, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), [this](int index)
    {
        if (!this->process_item->change_integrity_level(index))
        {
            QMessageBox::warning(this, tr("Error"), tr("Error changing integrity level"),  QMessageBox::Ok);
        }
        this->showCurrentIntegrity();
    });

}

SecurityDialog::~SecurityDialog()
{
    delete ui;
}

void SecurityDialog::createUi(const QStringList &header)
{
    ui->privilegeTable->setColumnCount(2);
    ui->privilegeTable->setShowGrid(false);
    ui->privilegeTable->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->privilegeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->privilegeTable->setHorizontalHeaderLabels(header);
    ui->privilegeTable->verticalHeader()->setVisible(false);
    ui->privilegeTable->setContextMenuPolicy(Qt::CustomContextMenu);
}

void SecurityDialog::fillPrivileges()
{
    process_item->fill_privileges();
    ui->privilegeTable->setRowCount(0);
    int i = 0;
    if (false == process_item->privileges_list_.empty())
    {
        for (auto it = process_item->privileges_list_.begin(); it != process_item->privileges_list_.end(); ++it)
        {
            ui->privilegeTable->insertRow(ui->privilegeTable->rowCount());

            QTableWidgetItem *nameItem = new QTableWidgetItem(convertToQString((*it).first));
            nameItem->setFlags(nameItem->flags() ^ Qt::ItemIsEditable);
            ui->privilegeTable->setItem(i, 0, nameItem);

            QTableWidgetItem *statusItem = new QTableWidgetItem(convertToQString((*it).second));
            statusItem->setFlags(statusItem->flags() ^ Qt::ItemIsEditable);
            ui->privilegeTable->setItem(i, 1, statusItem);
            i++;
        }

    }
    ui->privilegeTable->resizeColumnsToContents();
    ui->privilegeTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
}

void SecurityDialog::fillIntegrityBox()
{
    ui->intLvlBox->addItem(tr("Untrusted"));
    ui->intLvlBox->addItem(tr("Low Integrity"));
    ui->intLvlBox->addItem(tr("Medium Integrity"));
    ui->intLvlBox->addItem(tr("High Integrity"));
    ui->intLvlBox->addItem(tr("System Integrity"));
    this->showCurrentIntegrity();
}

void SecurityDialog::showCurrentIntegrity()
{
    process_item->fill_integrity_level();
    QString current_int_lvl = convertToQString(process_item->integrity_level_);
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

void SecurityDialog::slotShowContexMenu(QPoint pos)
{
    QMenu * menu = new QMenu(this);

    QAction * enableAction = new QAction(trUtf8("Enable"), this);
    QAction * disableAction = new QAction(trUtf8("Disable"), this);

    connect(enableAction, SIGNAL(triggered()), this, SLOT(slotEnablePrivelege()));
    connect(disableAction, SIGNAL(triggered()), this, SLOT(slotDisablePrivelege()));

    menu->addAction(enableAction);
    menu->addAction(disableAction);

    menu->popup(ui->privilegeTable->viewport()->mapToGlobal(pos));
}

void SecurityDialog::slotEnablePrivelege()
{
    int row = ui->privilegeTable->selectionModel()->currentIndex().row();
    QString privilege = ui->privilegeTable->item(row, 0)->text();
    std::wstring privelege_wstring = privilege.toStdWString();
    const wchar_t* wcs = privelege_wstring.c_str();
    if (!process_item->change_privileges(wcs, true))
    {
        QMessageBox::warning(this, tr("Error"), tr("Error enabling privilege"),  QMessageBox::Ok);
    }
    this->fillPrivileges();
}

void SecurityDialog::slotDisablePrivelege()
{
    int row = ui->privilegeTable->selectionModel()->currentIndex().row();
    QString privilege = ui->privilegeTable->item(row, 0)->text();
    std::wstring privelege_wstring = privilege.toStdWString();
    const wchar_t* wcs = privelege_wstring.c_str();
    if (!process_item->change_privileges(wcs, false))
    {
        QMessageBox::warning(this, tr("Error"), tr("Error disabling privilege"),  QMessageBox::Ok);
    }
    this->fillPrivileges();
}
