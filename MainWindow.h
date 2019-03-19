#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSortFilterProxyModel>

class ProcessListModel;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    ProcessListModel *model;
    QSortFilterProxyModel *proxyModel;
    void initializeProcessExplorer();

signals:
    void updateButtonPushed();

public slots:
    void slotCustomMenuRequested(QPoint);
    void slotShowSecutityDialog();
    void slotShowFileDialog();
    void slotShowFolderDialog();
};

#endif // MAINWINDOW_H
