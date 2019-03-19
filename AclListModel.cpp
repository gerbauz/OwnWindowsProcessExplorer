#include "AclListModel.h"
#include "AclListItem.h"
#include "FilesystemObject.h"


AclListModel::AclListModel(FilesystemObject *opened_file):
    file(opened_file)
{
    QList<QVariant> rootData;
    rootData << "User" << "SID" << "SID Type" << "ACE Type";
    root_item = new AclListItem(rootData);
    this->fillWithAcl(root_item);
}

AclListModel::~AclListModel()
{
    delete root_item;
}

int AclListModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return static_cast<AclListItem*>(parent.internalPointer())->columnCount();
    else
        return root_item->columnCount();
}

void AclListModel::fillWithAcl(AclListItem *parent)
{
    file->fill_acl_info();
    std::vector<ACL_INFO> acl_list = file->data_acl;

    for (auto acl_it = acl_list.begin(); acl_it != acl_list.end(); ++ acl_it)
    {
        QList<QVariant> columnData;
        columnData << QString::fromStdWString((*acl_it).username);
        columnData << QString::fromStdWString((*acl_it).SID);
        columnData << QString::fromStdWString((*acl_it).sid_type);
        columnData << QString::fromStdWString((*acl_it).ace_type);

        parent->appendChild(new AclListItem(columnData, parent));

        std::vector<std::wstring> rights_list = (*acl_it).access_rights;

        AclListItem *right_item = parent->child(parent->childCount() - 1);

        for (auto right_it = rights_list.begin(); right_it != rights_list.end(); ++right_it)
        {
            QList<QVariant> rightData;
            rightData << QString::fromStdWString(*right_it);
            right_item->appendChild(new AclListItem(rightData, right_item));
        }


    }

}

QVariant AclListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    AclListItem *item = static_cast<AclListItem*>(index.internalPointer());

    if (role != Qt::DisplayRole)
        return QVariant();

    return item->data(index.column());
}

Qt::ItemFlags AclListModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;

    return QAbstractItemModel::flags(index);
}

QVariant AclListModel::headerData(int section, Qt::Orientation orientation,
                                  int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        return root_item->data(section);

    return QVariant();
}

QModelIndex AclListModel::index(int row, int column, const QModelIndex &parent)
const
{
    if (!hasIndex(row, column, parent))
        return QModelIndex();

    AclListItem *parentItem;

    if (!parent.isValid())
        parentItem = root_item;
    else
        parentItem = static_cast<AclListItem*>(parent.internalPointer());

    AclListItem *childItem = parentItem->child(row);
    if (childItem)
        return createIndex(row, column, childItem);
    else
        return QModelIndex();
}

QModelIndex AclListModel::parent(const QModelIndex &index) const
{
    if (!index.isValid())
        return QModelIndex();

    AclListItem *childItem = static_cast<AclListItem*>(index.internalPointer());
    AclListItem *parentItem = childItem->parentItem();

    if (parentItem == root_item)
        return QModelIndex();

    return createIndex(parentItem->row(), 0, parentItem);
}

int AclListModel::rowCount(const QModelIndex &parent) const
{
    AclListItem *parentItem;
    if (parent.column() > 0)
        return 0;

    if (!parent.isValid())
        parentItem = root_item;
    else
        parentItem = static_cast<AclListItem*>(parent.internalPointer());

    return parentItem->childCount();
}
