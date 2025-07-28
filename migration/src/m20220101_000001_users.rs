use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.create_table(
            Table::create()
                .table(Users::Table)
                .col(
                    ColumnDef::new(Users::Id)
                        .integer()
                        .not_null()
                        .auto_increment()
                        .primary_key(),
                )
                .col(ColumnDef::new(Users::Pid).uuid().not_null().unique_key())
                .col(
                    ColumnDef::new(Users::Email)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(Users::Password).string().not_null())
                .col(
                    ColumnDef::new(Users::ApiKey)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(Users::Name).string().not_null())
                .col(ColumnDef::new(Users::ResetToken).string())
                .col(ColumnDef::new(Users::ResetSentAt).timestamp_with_time_zone())
                .col(ColumnDef::new(Users::EmailVerificationToken).string())
                .col(ColumnDef::new(Users::EmailVerificationSentAt).timestamp_with_time_zone())
                .col(ColumnDef::new(Users::EmailVerifiedAt).timestamp_with_time_zone())
                .col(ColumnDef::new(Users::MagicLinkToken).string())
                .col(ColumnDef::new(Users::MagicLinkExpiration).timestamp_with_time_zone())
                .col(ColumnDef::new(Users::TOTPSecret).string())
                .col(ColumnDef::new(Users::TOTPVerifiedAt).timestamp_with_time_zone())
                .col(ColumnDef::new(Users::TOTPLoginToken).string())
                .col(ColumnDef::new(Users::TOTPLoginTokenExpiration).timestamp_with_time_zone())
                .col(
                    ColumnDef::new(Users::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null()
                        .default(Expr::current_timestamp()),
                )
                .col(
                    ColumnDef::new(Users::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null()
                        .default(Expr::current_timestamp()),
                )
                .to_owned(),
        )
        .await?;
        Ok(())
    }

    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        m.drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;
        Ok(())
    }
}

#[derive(Iden)]
pub enum Users {
    Table,
    Id,
    Pid,
    Email,
    Password,
    ApiKey,
    Name,
    ResetToken,
    ResetSentAt,
    EmailVerificationToken,
    EmailVerificationSentAt,
    EmailVerifiedAt,
    MagicLinkToken,
    MagicLinkExpiration,
    TOTPSecret,
    TOTPLoginToken,
    TOTPLoginTokenExpiration,
    TOTPVerifiedAt,
    CreatedAt,
    UpdatedAt,
}
