using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityAuth.Migrations
{
    public partial class SeedingRoleViaModelBuilder : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "75d9d6a0-e0aa-4c9d-ba90-39497bad4b6d", "d353fd1a-e628-426f-9228-904fdcc74105", "user", "USER" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "cb13728b-b73d-41ca-a462-ac33e0e253b0", "6e57818e-be0c-4395-99f9-adc56aec8eb1", "Administrator", "ADMINISTRATOR" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "75d9d6a0-e0aa-4c9d-ba90-39497bad4b6d");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "cb13728b-b73d-41ca-a462-ac33e0e253b0");
        }
    }
}
