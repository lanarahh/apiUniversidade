﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;
using apiUniversidade.Context;

#nullable disable

namespace apiUniversidade.Migrations
{
    [DbContext(typeof(ApiUniversidadeContext))]
    partial class ApiUniversidadeContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "7.0.9")
                .HasAnnotation("Relational:MaxIdentifierLength", 63);

            NpgsqlModelBuilderExtensions.UseIdentityByDefaultColumns(modelBuilder);

            modelBuilder.Entity("apiUniversidade.Model.Aluno", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<int>("Id"));

                    b.Property<int?>("CursoId")
                        .HasColumnType("integer");

                    b.Property<DateTime>("DataNascimento")
                        .HasColumnType("timestamp with time zone");

                    b.Property<string>("Nome")
                        .HasColumnType("text");

                    b.Property<string>("cpf")
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.HasIndex("CursoId");

                    b.ToTable("Alunos");
                });

            modelBuilder.Entity("apiUniversidade.Model.Curso", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<int>("Id"));

                    b.Property<string>("Area")
                        .HasColumnType("text");

                    b.Property<int>("Duracao")
                        .HasColumnType("integer");

                    b.Property<string>("Nome")
                        .HasColumnType("text");

                    b.HasKey("Id");

                    b.ToTable("Cursos");
                });

            modelBuilder.Entity("apiUniversidade.Model.Disciplina", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("integer");

                    NpgsqlPropertyBuilderExtensions.UseIdentityByDefaultColumn(b.Property<int>("Id"));

                    b.Property<int>("CargaHoraria")
                        .HasColumnType("integer");

                    b.Property<int?>("CursoId")
                        .HasColumnType("integer");

                    b.Property<string>("Nome")
                        .HasColumnType("text");

                    b.Property<int>("Semestre")
                        .HasColumnType("integer");

                    b.HasKey("Id");

                    b.HasIndex("CursoId");

                    b.ToTable("Disciplinas");
                });

            modelBuilder.Entity("apiUniversidade.Model.Aluno", b =>
                {
                    b.HasOne("apiUniversidade.Model.Curso", null)
                        .WithMany("alunos")
                        .HasForeignKey("CursoId");
                });

            modelBuilder.Entity("apiUniversidade.Model.Disciplina", b =>
                {
                    b.HasOne("apiUniversidade.Model.Curso", null)
                        .WithMany("disciplinas")
                        .HasForeignKey("CursoId");
                });

            modelBuilder.Entity("apiUniversidade.Model.Curso", b =>
                {
                    b.Navigation("alunos");

                    b.Navigation("disciplinas");
                });
#pragma warning restore 612, 618
        }
    }
}