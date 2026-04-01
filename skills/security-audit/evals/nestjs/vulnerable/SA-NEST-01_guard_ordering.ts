// SA-NEST-01: RolesGuard before AuthGuard — roles checked without authentication
import { Controller, Get, UseGuards } from '@nestjs/common';
import { RolesGuard } from './roles.guard';
import { AuthGuard } from './auth.guard';

@Controller('admin')
@UseGuards(RolesGuard, AuthGuard)
export class AdminController {
  @Get('dashboard')
  getDashboard() {
    return this.adminService.getDashboard();
  }
}
