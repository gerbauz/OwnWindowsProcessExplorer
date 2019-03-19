#include "ProcessListItem.h"

ProcessListItem::ProcessListItem(const QList<QVariant> &data, ProcessListItem *parent, std::shared_ptr<ProcessInfoItem> item)
{
    p_parent_item = parent;
    item_data = data;
    process_item = item;
    item_process_data.setValue(process_item);
}

void ProcessListItem::appendChild(ProcessListItem *item)
{
    child_items.append(item);
}

ProcessListItem *ProcessListItem::child(int row)
{
    return child_items.value(row);
}

int ProcessListItem::childCount() const
{
    return child_items.count();
}

int ProcessListItem::columnCount() const
{
    return item_data.count();
}

QVariant ProcessListItem::data(int column) const
{
    return item_data.value(column);
}

QVariant ProcessListItem::process_data() const
{
    return item_process_data;
}

ProcessListItem *ProcessListItem::parentItem()
{
    return p_parent_item;
}

int ProcessListItem::row() const
{
    if (p_parent_item)
        return p_parent_item->child_items.indexOf(const_cast<ProcessListItem*>(this));

    return 0;
}
