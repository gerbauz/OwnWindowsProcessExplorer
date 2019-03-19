#include "ProcessListItem.h"
#include "ProcessListModel.h"
#include "ProcessInfo.h"
#include <QString>
#include <memory>

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

ProcessListModel::ProcessListModel()
{
    QList<QVariant> rootData;
    rootData << "Process" << "PID" << "File Path" << "Owner Name" << "SID" << "DEP" << "ASLR" << "Image Type" ;
    root_item = new ProcessListItem(rootData);

    pi = new ProcessInfo;
    pi->make_process_list();

    this->fillWithProcesses(*pi, root_item);
}

ProcessListModel::~ProcessListModel()
{
    delete root_item;
    delete pi;
}

int ProcessListModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return static_cast<ProcessListItem*>(parent.internalPointer())->columnCount();
    else
        return root_item->columnCount();
}

void ProcessListModel::fillWithProcesses(ProcessInfo data, ProcessListItem *parent)
{

    std::vector<std::shared_ptr<ProcessInfoItem>> process_list = data.get_process_list();

    for (auto process_item_it = process_list.begin(); process_item_it != process_list.end(); ++process_item_it)
    {
        QList<QVariant> columnData;
        columnData << convertToQString((*process_item_it)->process_name_);
        columnData << convertToQString((*process_item_it)->pid_);
        columnData << convertToQString((*process_item_it)->file_path_);
        columnData << convertToQString((*process_item_it)->owner_name_);
        columnData << convertToQString((*process_item_it)->owner_sid_string_);
        columnData << convertToQString((*process_item_it)->DEP_usage);
        columnData << convertToQString((*process_item_it)->ASLR_usage);
        columnData << convertToQString((*process_item_it)->type_of_process_);
        parent->appendChild(new ProcessListItem(columnData, parent, *process_item_it));
        ProcessListItem *dll_item = parent->child(parent->childCount() - 1);

        for (auto dll_it = (*process_item_it)->dll_list_.begin(); dll_it != (*process_item_it)->dll_list_.end(); ++dll_it)
        {
            QList<QVariant> dllData;
            dllData << convertToQString(*dll_it);
            dll_item->appendChild(new ProcessListItem(dllData, dll_item));
        }
    }
}

QVariant ProcessListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    ProcessListItem *item = static_cast<ProcessListItem*>(index.internalPointer());

    if (role == Qt::UserRole + 1)
    {
        return item->process_data();
    }

    if (role != Qt::DisplayRole)
        return QVariant();

    return item->data(index.column());
}

Qt::ItemFlags ProcessListModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    return QAbstractItemModel::flags(index);
}

QVariant ProcessListModel::headerData(int section, Qt::Orientation orientation,
                                      int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        return root_item->data(section);

    return QVariant();
}

QModelIndex ProcessListModel::index(int row, int column, const QModelIndex &parent)
const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    ProcessListItem *parentItem;

    if (!parent.isValid())
        parentItem = root_item;
    else
        parentItem = static_cast<ProcessListItem*>(parent.internalPointer());

    ProcessListItem *childItem = parentItem->child(row);
    if (childItem)
        return createIndex(row, column, childItem);
    else
        return QModelIndex();
}

QModelIndex ProcessListModel::parent(const QModelIndex &index) const
{
    if (!index.isValid())
        return QModelIndex();

    ProcessListItem *childItem = static_cast<ProcessListItem*>(index.internalPointer());
    ProcessListItem *parentItem = childItem->parentItem();

    if (parentItem == root_item)
        return QModelIndex();

    return createIndex(parentItem->row(), 0, parentItem);
}

int ProcessListModel::rowCount(const QModelIndex &parent) const
{
    ProcessListItem *parentItem;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parentItem = root_item;
    else
        parentItem = static_cast<ProcessListItem*>(parent.internalPointer());

    return parentItem->childCount();
}
