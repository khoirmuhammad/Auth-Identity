using AutoMapper;
using IdentityAuth.Models.CustomModels;
using IdentityAuth.Models;

namespace IdentityAuth.Helpers
{
    public class AutoMapperProfiles : Profile
    {
        public AutoMapperProfiles()
        {
            CreateMap<UserRegistrationModel, User>()
                .ForMember(u => u.UserName, opt => opt.MapFrom(x => x.Email));
        }
    }
}
