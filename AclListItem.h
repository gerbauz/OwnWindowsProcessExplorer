#ifndef ACLLISTITEM_H
#define ACLLISTITEM_H

#include <QList>
#include <QVariant>

class AclListItem
{

private:
    AclListItem *p_parent_item;
    QList<AclListItem*> child_items;
    QList<QVariant> item_data;

public:
    AclListItem(const QList<QVariant> &data, AclListItem *parent = nullptr);
    ~AclListItem() {}

    void appendChild(AclListItem *child);

    AclListItem *child(int row);
    int childCount() const;
    int columnCount() const;
    QVariant data(int column) const;
    int row() const;
    AclListItem *parentItem();
    std::shared_ptr<AclListItem> process_item;
};

#endif // ACLLISTITEM_H
