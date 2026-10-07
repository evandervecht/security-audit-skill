// SA-NEST-01: Safe — AuthGuard before RolesGuard
import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesAuthGuard } from './roles-auth.guard';
import { Roles } from './roles.decorator';

@Controller('admin')
@UseGuards(JwtAuthGuard, RolesAuthGuard)
@Roles('admin')
export class AdminController {
  @Get('dashboard')
  getDashboard() {
    return this.adminService.getDashboard();
  }
}
