#include "MainWindow.h"
#include "ui_mainwindow.h"
#include "ProcessListModel.h"
#include "ProcessListItem.h"
#include "ProcessInfoItem.h"
#include "SecurityDialog.h"
#include "FileDialog.h"
#include <QStandardItemModel>
#include <QMessageBox>
#include <QFileDialog>
#include <memory>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setWindowTitle("Own Process Explorer");
    this->initializeProcessExplorer();
    ui->processTable->setFont(QFont("Times", 10));
    ui->processTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->processTable, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(slotCustomMenuRequested(QPoint)));
    connect(ui->updateButton, &QPushButton::clicked, [this]
    {
        delete model;
        initializeProcessExplorer();
    });

    connect(ui->openFileAction, SIGNAL(triggered()), this, SLOT(slotShowFileDialog()));
    connect(ui->openFolderAction, SIGNAL(triggered()), this, SLOT(slotShowFolderDialog()));
    connect(ui->exitAction, SIGNAL(triggered()), this, SLOT(close()));
}

MainWindow::~MainWindow()
{
    delete model;
    delete ui;
}

void MainWindow::initializeProcessExplorer()
{
    model = new ProcessListModel;
    ui->processTable->setModel(model);
}

void MainWindow::slotCustomMenuRequested(QPoint pos)
{
    QMenu * menu = new QMenu(this);
    QAction * securityTab = new QAction(trUtf8("Security Information"), this);
    connect(securityTab, SIGNAL(triggered()), this, SLOT(slotShowSecutityDialog()));
    menu->addAction(securityTab);
    menu->popup(ui->processTable->viewport()->mapToGlobal(pos));

}

void MainWindow::slotShowSecutityDialog()
{
    QVariant qv = ui->processTable->selectionModel()->currentIndex().data(Qt::UserRole + 1);
    std::shared_ptr<ProcessInfoItem> item = qv.value<std::shared_ptr<ProcessInfoItem>>();
    if (item)
    {
        SecurityDialog *security_dialog = new SecurityDialog(this, qv.value<std::shared_ptr<ProcessInfoItem>>());
        security_dialog->show();
    }
}

void MainWindow::slotShowFileDialog()
{
    QString filename =  QFileDialog::getOpenFileName(
                this,
                "Open File",
                QDir::currentPath(),
                "All files (*.*)");
    if (filename.size())
    {
        FileDialog *file_dialog = new FileDialog(this, filename);
        file_dialog->show();
    }

}

void MainWindow::slotShowFolderDialog()
{
    QString foldername =  QFileDialog::getExistingDirectory(
                this,
                "Open Folder",
                QDir::currentPath());
    if (foldername.size())
    {
        FileDialog *file_dialog = new FileDialog(this, foldername);
        file_dialog->show();
    }
}
