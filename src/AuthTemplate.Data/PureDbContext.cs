using AuthTemplate.Data.Entities.PureIdentity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthTemplate.Data;
public class PureDbContext(DbContextOptions<PureDbContext> options) : DbContext(options)
{
    public DbSet<ApplicationUser> Users { get; set; } = null!;

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) => base.OnConfiguring(optionsBuilder);

    protected override void OnModelCreating(ModelBuilder modelBuilder) => base.OnModelCreating(modelBuilder);
}
