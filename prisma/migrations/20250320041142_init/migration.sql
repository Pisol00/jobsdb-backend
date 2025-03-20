-- AlterTable
ALTER TABLE "users" ADD COLUMN     "profile_image" TEXT,
ADD COLUMN     "provider" TEXT,
ADD COLUMN     "provider_id" TEXT,
ALTER COLUMN "password" DROP NOT NULL;
