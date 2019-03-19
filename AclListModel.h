#ifndef ACLLISTMODEL_H
#define ACLLISTMODEL_H

#include <QAbstractItemModel>
#include <QVariant>

class AclListItem;
class FilesystemObject;

class AclListModel : public QAbstractItemModel
{
    Q_OBJECT

private:
    AclListItem *root_item;
    FilesystemObject *file;
    void fillWithAcl(AclListItem *parent);

public:
    AclListModel(FilesystemObject *opened_file = nullptr);
    ~AclListModel() override;
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

#endif // ACLLISTMODEL_H
