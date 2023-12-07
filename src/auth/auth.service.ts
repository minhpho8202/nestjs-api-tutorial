import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as argon from 'argon2'
import { AuthDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
    constructor(private prismaService: PrismaService) { }

    async signup(dto: AuthDto) {
        try {
            const hash = await argon.hash(dto.password)

            const user = await this.prismaService.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            })

            delete user.hash

            return user
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken')
                }
            }

            throw error
        }
    }

    async signin(dto: AuthDto) {
        try {
            const user = await this.prismaService.user.findUnique({
                where: {
                    email: dto.email
                },
            })

            if (!user) {
                throw new ForbiddenException('Credentials taken')
            }

            const checkPassword = await argon.verify(user.hash, dto.password)

            if (!checkPassword) {
                throw new ForbiddenException('Credentials taken')
            }

            delete user.hash

            return user;

        } catch (error) {
            throw error
        }
    }
}
