-- AlterTable
ALTER TABLE "users" ADD COLUMN     "email_verify_expires" TIMESTAMP(3),
ADD COLUMN     "email_verify_token" TEXT,
ADD COLUMN     "is_email_verified" BOOLEAN NOT NULL DEFAULT false;
