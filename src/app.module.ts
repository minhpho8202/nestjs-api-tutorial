import { Module } from '@nestjs/common';
import { PrismaModule } from './prisma/prisma.module';
import { BookmarkModule } from './bookmark/bookmark.module';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';

@Module({
  imports: [AuthModule, UserModule, BookmarkModule, PrismaModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
