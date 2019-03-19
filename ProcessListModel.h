#ifndef PROCESSLISTMODEL_H
#define PROCESSLISTMODEL_H

#include <QAbstractItemModel>
#include <QVariant>

#include "ProcessInfo.h"

class ProcessListItem;

class ProcessListModel : public QAbstractItemModel
{

    Q_OBJECT

private:
    ProcessListItem *root_item;
    ProcessInfo *pi;
    void fillWithProcesses(ProcessInfo data, ProcessListItem *parent);

public:
    ProcessListModel();
    ~ProcessListModel() override;
    QVariant data(const QModelIndex &index, int role) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;
    QModelIndex index(int row, int column,
                      const QModelIndex &parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex &index) const override;
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;



};


#endif // PROCESSLISTMODEL_H
