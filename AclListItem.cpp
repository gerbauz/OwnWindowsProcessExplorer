#include "AclListItem.h"


AclListItem::AclListItem(const QList<QVariant> &data, AclListItem *parent)
{
    p_parent_item = parent;
    item_data = data;
}

void AclListItem::appendChild(AclListItem *item)
{
    child_items.append(item);
}

AclListItem *AclListItem::child(int row)
{
    return child_items.value(row);
}

int AclListItem::childCount() const
{
    return child_items.count();
}

int AclListItem::columnCount() const
{
    return item_data.count();
}

QVariant AclListItem::data(int column) const
{
    return item_data.value(column);
}

AclListItem *AclListItem::parentItem()
{
    return p_parent_item;
}

int AclListItem::row() const
{
    if (p_parent_item)
        return p_parent_item->child_items.indexOf(const_cast<AclListItem*>(this));

    return 0;
}
