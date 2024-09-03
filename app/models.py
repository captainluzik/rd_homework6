from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.sql import func
from sqlalchemy import Table, Column, ForeignKey, String, Integer, DateTime, Text, Float
from datetime import datetime


class Base(DeclarativeBase, AsyncAttrs):
    pass


cve_references_association = Table(
    "cve_references", Base.metadata,
    Column("cve_record_id", String, ForeignKey("cve_records.id")),
    Column("reference_id", Integer, ForeignKey("references.id"))
)


class CVERecord(Base):
    __tablename__ = "cve_records"

    id: Mapped[str] = mapped_column(
        String(30),
        primary_key=True,
        index=True,
    )
    assigner_org_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), server_default=func.gen_random_uuid())
    state: Mapped[str] = mapped_column(String())
    assigner_short_name: Mapped[str] = mapped_column(String())
    date_reserved: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    date_published: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    date_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    title = mapped_column(String())
    description = mapped_column(Text())

    problem_types = relationship("ProblemType", back_populates="cve_record", cascade="all, delete-orphan")
    references = relationship("Reference", secondary=cve_references_association, back_populates="cve_records")
    affected_products = relationship("AffectedProduct", back_populates="cve_record", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<CVERecord(id={self.id}, title={self.title})>"

    @classmethod
    def from_dict(cls, data: dict) -> "CVERecord":
        date_reserved = datetime.fromisoformat(data["dateReserved"]) if (
            date_reserved := data.get("dateReserved")) else None
        date_published = datetime.fromisoformat(data["datePublished"]) if (
            date_published := data.get("datePublished")) else None
        date_updated = datetime.fromisoformat(data["dateUpdated"]) if (
            date_updated := data.get("dateUpdated")) else None

        return cls(
            id=data.get("cveId"),
            assigner_org_id=data.get("assignerOrgId"),
            state=data.get("state"),
            assigner_short_name=data.get("assignerShortName"),
            date_reserved=date_reserved,
            date_published=date_published,
            date_updated=date_updated,
        )


class ProblemType(Base):
    __tablename__ = "problem_types"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    cve_record_id: Mapped[str] = mapped_column(String, ForeignKey("cve_records.id"))
    description: Mapped[str] = mapped_column(String)

    cve_record = relationship("CVERecord", back_populates="problem_types")

    def __repr__(self):
        return f"<ProblemType(id={self.id}, description={self.description})>"

    @classmethod
    def from_dict(cls, data: dict, cve_record: CVERecord) -> "ProblemType":
        return cls(
            description=data.get("description"),
            cve_record=cve_record,
        )


class Reference(Base):
    __tablename__ = "references"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    url: Mapped[str] = mapped_column(String)
    tags: Mapped[str] = mapped_column(String)

    cve_records = relationship("CVERecord", secondary=cve_references_association, back_populates="references")

    def __repr__(self):
        return f"<Reference(id={self.id}, url={self.url})>"

    @classmethod
    def from_dict(cls, data: dict) -> "Reference":
        return cls(
            url=data.get("url"),
            tags=", ".join(data.get("tags", [])),
        )


class AffectedProduct(Base):
    __tablename__ = "affected_products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    cve_record_id: Mapped[str] = mapped_column(String, ForeignKey("cve_records.id"))
    vendor: Mapped[str] = mapped_column(String)
    product: Mapped[str] = mapped_column(String)
    default_status: Mapped[str] = mapped_column(String)

    cve_record = relationship("CVERecord", back_populates="affected_products")
    versions = relationship("ProductVersion", back_populates="affected_product", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<AffectedProduct(id={self.id}, vendor={self.vendor}, product={self.product})>"

    @classmethod
    def from_dict(cls, data: dict, cve_record: CVERecord) -> "AffectedProduct":
        return cls(
            vendor=data.get("vendor"),
            product=data.get("product"),
            default_status=data.get("defaultStatus"),
            cve_record=cve_record,
        )


class ProductVersion(Base):
    __tablename__ = "product_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    affected_product_id: Mapped[int] = mapped_column(Integer, ForeignKey("affected_products.id"))
    version: Mapped[str] = mapped_column(String)
    less_than: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    version_type: Mapped[str] = mapped_column(String)

    affected_product = relationship("AffectedProduct", back_populates="versions")

    def __repr__(self):
        return f"<ProductVersion(id={self.id}, version={self.version})>"

    @classmethod
    def from_dict(cls, data: dict, affected_product: AffectedProduct) -> "ProductVersion":
        return cls(
            version=data.get("version"),
            less_than=data.get("lessThan"),
            status=data.get("status"),
            version_type=data.get("versionType"),
            affected_product=affected_product,
        )
