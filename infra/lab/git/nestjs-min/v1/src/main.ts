import 'reflect-metadata';
import { Controller, Get, Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

@Controller()
class AppController {
  @Get('healthz')
  health() {
    return { status: 'ok', app: 'nestjs-min' };
  }

  @Get()
  index() {
    return { hello: 'nestjs-min v1' };
  }
}

@Module({ controllers: [AppController] })
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(Number(process.env.PORT ?? 3000), '0.0.0.0');
}
void bootstrap();
