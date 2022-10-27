using Optimizely_Okta.Models.Pages;
using Optimizely_Okta.Models.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace Optimizely_Okta.Controllers;

public class SearchPageController : PageControllerBase<SearchPage>
{
    public ViewResult Index(SearchPage currentPage, string q)
    {
        var model = new SearchContentModel(currentPage)
        {
            Hits = Enumerable.Empty<SearchContentModel.SearchHit>(),
            NumberOfHits = 0,
            SearchServiceDisabled = true,
            SearchedQuery = q
        };

        return View(model);
    }
}
