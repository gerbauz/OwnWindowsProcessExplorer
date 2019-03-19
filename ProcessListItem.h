#ifndef PROCESSLISTITEM_H
#define PROCESSLISTITEM_H

#include <QList>
#include <QVariant>
#include <memory>

#include "ProcessInfoItem.h"

class ProcessListItem
{

private:
    ProcessListItem *p_parent_item;
    QList<ProcessListItem*> child_items;
    QList<QVariant> item_data;
    QVariant item_process_data;


public:
    ProcessListItem(const QList<QVariant> &data, ProcessListItem *parent = nullptr, std::shared_ptr<ProcessInfoItem> p_item = nullptr);
    ~ProcessListItem() {}

    void appendChild(ProcessListItem *child);

    ProcessListItem *child(int row);
    int childCount() const;
    int columnCount() const;
    QVariant data(int column) const;
    QVariant process_data() const;
    int row() const;
    ProcessListItem *parentItem();
    std::shared_ptr<ProcessInfoItem> process_item;

};

#endif // PROCESSLISTITEM_H
